import bcrypt from 'bcrypt';
import jwt, { SignOptions, JwtPayload, Secret } from 'jsonwebtoken';
import DotenvConfig from '@config/dotenv.config';
import {
  BadRequest,
  InvalidInput,
  ResourceNotFound,
  Unauthorized,
  TooManyRequests,
} from '@middlewares/error.middleware';
// import { userRepo } from '@user/user.entity';
import { ISignin, ISignup, TokenPayload, TokenType } from './auth.type';
import { IUser } from '@user/user.type';
// import { loginAttemptRepo, tokenRepo } from './auth.entity';
import { generateRandomHexString } from '@utils/crypto.utils';
import { generateOTP, verifyOTP } from '@utils/otp.utils';
import { AppDataSource } from '@config/data.source';
import { User } from '@user/user.entity';
import { LoginAttempt, Token } from './auth.entity';
import {
  signinValidationSchema,
  signupValidationSchema,
  forgotPasswordValidationSchema,
  verifyOTPValidationSchema,
  resendOTPValidationSchema,
} from '@validations/auth.validations';
import DeviceService from '@security/device.service';
import ActivityService from '@security/activity.service';
import { Event } from '@security/activity.type';
import { MailServiceClient, getMailClient } from '@grpc/client/mail.client';

const userRepo = AppDataSource.getRepository(User);
const loginAttemptRepo = AppDataSource.getRepository(LoginAttempt);
const tokenRepo = AppDataSource.getRepository(Token);
const mailClient = getMailClient();

export default class AuthService {
  private static JWT_OPTIONS: SignOptions = {
    issuer: DotenvConfig.JWTHeader.issuer,
    audience: DotenvConfig.JWTHeader.audience,
    algorithm: DotenvConfig.JWTHeader.algorithm,
  };

  private static async hashPassword(password: string): Promise<string> {
    if (!password) throw new InvalidInput('Password is required');
    return bcrypt.hash(password, DotenvConfig.BcryptSalt);
  }

  static async signup(
    payload: ISignup,
    ipAddress?: string,
    userAgent?: string,
    location?: string
  ) {
    const exisitingUser = await userRepo.findOneBy({ email: payload.email });
    if (exisitingUser) throw new BadRequest('Email already exists');

    const otp = generateOTP();
    const hashedPassword = await this.hashPassword(payload.password);

    const newUser = userRepo.create({
      firstName: payload.firstName,
      lastName: payload.lastName,
      email: payload.email,
      password: hashedPassword,
      appRole: payload.appRole,
    });

    await userRepo.save(newUser);

    await tokenRepo.save(
      tokenRepo.create({
        userId: newUser.id,
        token: await bcrypt.hash(otp, DotenvConfig.BcryptSalt),
        tokenType: TokenType.EMAIL_VERIFICATION,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
      })
    );

    // Fire-and-forget: non-critical operations
    ActivityService.log(Event.USER_REGISTERED, {
      userId: newUser.id,
      ip: ipAddress,
      userAgent,
      location,
      metadata: {
        email: newUser.email,
        appRole: newUser.appRole,
      },
    }).catch((err) => console.error('Activity log error:', err));

    DeviceService.registerOrUpdate(newUser.id, ipAddress, userAgent, {
      isTrusted: false,
    }).catch((err) => console.error('Device registration error:', err));

    // Send verification email (still awaited - critical for user flow)
    await mailClient.sendVerificationEmail({
      recipientEmail: newUser.email,
      verificationCode: otp,
    });
    return newUser;
  }

  static async signin(
    payload: ISignin,
    ipAddress: string,
    userAgent?: string,
    location?: string
  ) {
    const user = await userRepo.findOneBy({ email: payload.email });
    if (!user) {
      this.logFailedAttempt(payload.email, ipAddress);
      await ActivityService.log(Event.LOGIN_FAILED, {
        userId: null,
        ip: ipAddress,
        userAgent,
        location,
        metadata: { email: payload.email, reason: 'user_not_found' },
      });
      console.log('activity log: user not found');
      throw new ResourceNotFound('Invalid credentials');
    }

    this.checkLoginCooldown(user, ipAddress);

    const isPasswordValid = await bcrypt.compare(
      payload.password,
      user.password
    );
    if (!isPasswordValid) {
      await this.handleInvalidPassword(
        user,
        payload.email,
        ipAddress,
        userAgent,
        location
      );
    }

    if (!user.isVerified) await this.handleUnverifiedAccount(user);

    await this.resetLoginAttempts(user);

    const { device } = await DeviceService.registerOrUpdate(
      user.id,
      ipAddress,
      userAgent,
      { isTrusted: false }
    );

    // Fire-and-forget: activity logging
    ActivityService.log(Event.LOGIN_SUCCESS, {
      userId: user.id,
      ip: ipAddress,
      userAgent,
      location,
      deviceId: device.deviceId,
      metadata: {
        deviceType: device.deviceType,
      },
    }).catch((err) => console.error('Activity log error:', err));

    const { accessToken, refreshToken } = await this.generateTokens(user);
    return { accessToken, refreshToken, user, device };
  }

  static async verifyOTP(
    email: string,
    otp: string,
    ipAddress?: string,
    userAgent?: string,
    location?: string
  ) {
    const user = await userRepo.findOneBy({ email });
    if (!user) throw new ResourceNotFound('User not found');

    if (user.isVerified) throw new BadRequest('Account is already verified');

    const existingToken = await tokenRepo.findOneBy({
      userId: user.id,
      tokenType: TokenType.EMAIL_VERIFICATION,
    });

    if (!existingToken) throw new BadRequest('Verification token not found');

    // Check if token has expired
    if (existingToken.expiresAt && new Date() > existingToken.expiresAt) {
      await tokenRepo.delete({ id: existingToken.id });
      throw new Unauthorized('OTP has expired. Please request a new one.');
    }

    const isTokenValid = verifyOTP(otp, existingToken.token);
    if (!isTokenValid) {
      await ActivityService.log(Event.EMAIL_VERIFICATION_FAILED, {
        userId: user.id,
        ip: ipAddress,
        userAgent,
        location,
        metadata: { email: user.email },
      });

      throw new Unauthorized('Invalid or expired otp');
    }

    await userRepo.save({ ...user, isVerified: true });

    await tokenRepo.delete({ id: existingToken.id });

    // Fire-and-forget: activity logging
    ActivityService.log(Event.EMAIL_VERIFIED, {
      userId: user.id,
      ip: ipAddress,
      userAgent,
      location,
      metadata: { email: user.email },
    }).catch((err) => console.error('Activity log error:', err));

    await mailClient.sendWelcomeEmail({
      recipientEmail: user.email,
      firstName: user.firstName,
    });

    return true;
  }

  static async resendOTP(
    email: string,
    ipAddress?: string,
    userAgent?: string,
    location?: string
  ) {
    const { error } = resendOTPValidationSchema.validate({ email });
    if (error) {
      const errorMessages: string[] = error.details.map(
        (detail) => detail.message
      );
      throw new InvalidInput(errorMessages.join(', '));
    }

    const user = await userRepo.findOneBy({ email });
    if (!user) throw new ResourceNotFound('Email not found');

    await tokenRepo.delete({
      userId: user.id,
      tokenType: TokenType.EMAIL_VERIFICATION,
    });

    const otp = generateOTP();
    const hashedOTP = await bcrypt.hash(otp, DotenvConfig.BcryptSalt);

    await tokenRepo.save(
      tokenRepo.create({
        userId: user.id,
        token: hashedOTP,
        tokenType: TokenType.EMAIL_VERIFICATION,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
      })
    );

    // Fire-and-forget: activity logging
    ActivityService.log(Event.OTP_RESENT, {
      userId: user.id,
      ip: ipAddress,
      userAgent,
      location,
      metadata: { email: user.email },
    }).catch((err) => console.error('Activity log error:', err));

    await mailClient.sendVerificationEmail({
      recipientEmail: user.email,
      verificationCode: otp,
    });

    return user;
  }

  static async forgotPassword(
    email: string,
    ipAddress?: string,
    userAgent?: string,
    location?: string
  ) {
    const { error } = forgotPasswordValidationSchema.validate({ email });
    if (error) {
      const errorMessages = error.details.map((detail) => detail.message);
      throw new InvalidInput(errorMessages.join(', '));
    }

    const existingUser = await userRepo.findOneBy({ email });
    if (!existingUser) throw new ResourceNotFound('User not found');

    await tokenRepo.delete({
      userId: existingUser.id,
      tokenType: TokenType.RESET_PASSWORD,
    });

    const otp = generateOTP();
    const hashedOTP = await bcrypt.hash(otp, DotenvConfig.BcryptSalt);

    const token = await tokenRepo.save(
      tokenRepo.create({
        userId: existingUser.id,
        token: hashedOTP,
        tokenType: TokenType.RESET_PASSWORD,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
      })
    );

    // Fire-and-forget: activity logging
    ActivityService.log(Event.PASSWORD_RESET_REQUESTED, {
      userId: existingUser.id,
      ip: ipAddress,
      userAgent,
      location,
      metadata: { email: existingUser.email },
    }).catch((err) => console.error('Activity log error:', err));

    await mailClient.sendPasswordResetEmail({
      recipientEmail: existingUser.email,
      firstName: existingUser.firstName,
      resetLink: `${DotenvConfig.frontendBaseURL}/resetpassword?token=${otp}&id=${token.id}`,
    });

    return token;
  }

  static async resetPassword(
    userId: string,
    newPassword: string,
    ipAddress?: string,
    userAgent?: string,
    location?: string
  ) {
    const user = await userRepo.findOneBy({ id: userId });
    if (!user) throw new ResourceNotFound('User not found');

    const hashedPassword = await this.hashPassword(newPassword);
    user.password = hashedPassword;
    await userRepo.save(user);

    await tokenRepo.delete({
      userId: user.id,
      tokenType: TokenType.RESET_PASSWORD,
    });

    // Fire-and-forget: activity logging
    ActivityService.log(Event.PASSWORD_RESET_SUCCESS, {
      userId: user.id,
      ip: ipAddress,
      userAgent,
      location,
      metadata: { email: user.email },
    }).catch((err) => console.error('Activity log error:', err));

    return true;
  }

  static async logout(
    userId: string,
    ipAddress?: string,
    userAgent?: string,
    location?: string
  ) {
    // Fire-and-forget: activity logging
    ActivityService.log(Event.LOGOUT, {
      userId,
      ip: ipAddress,
      userAgent,
      location,
    }).catch((err) => console.error('Activity log error:', err));

    return true;
  }

  private static async logFailedAttempt(email: string, ipAddress: string) {
    loginAttemptRepo.create({ email, success: false, ipAddress });
  }

  private static checkLoginCooldown(user: IUser, ipAddress: string) {
    if (user.loginCooldown && Date.now() < user.loginCooldown.getTime()) {
      this.logFailedAttempt(user.email, ipAddress);
      throw new TooManyRequests(
        `Account locked due to multiple failed login attempts. Try again after ${user.loginCooldown}`,
        { cooldown: user.loginCooldown }
      );
    }
  }

  private static async handleInvalidPassword(
    user: IUser,
    email: string,
    ipAddress: string,
    userAgent?: string,
    location?: string
  ) {
    user.loginAttempts += 1;

    if (user.loginAttempts >= user.allowedLoginAttempts) {
      user.loginCooldown = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
      user.loginAttempts = 0;

      await userRepo.save(user);

      await ActivityService.log(Event.ACCOUNT_LOCKED, {
        userId: user.id,
        ip: ipAddress,
        userAgent,
        location,
        metadata: {
          reason: 'too_many_failed_attempts',
          cooldownUntil: user.loginCooldown,
        },
      });

      throw new TooManyRequests(
        `Account locked due to multiple failed login attempts. Try again after ${user.loginCooldown}`
      );
    }

    await userRepo.save(user);
    this.logFailedAttempt(email, ipAddress);

    await ActivityService.log(Event.LOGIN_FAILED, {
      userId: user.id,
      ip: ipAddress,
      userAgent,
      location,
      metadata: {
        reason: 'invalid_password',
        attemptsRemaining: user.allowedLoginAttempts - user.loginAttempts,
      },
    });

    throw new Unauthorized(
      `Invalid credentials. ${user.allowedLoginAttempts - user.loginAttempts} attempt(s) remaining`
    );
  }

  private static async handleUnverifiedAccount(user: IUser) {
    const verifyToken = generateRandomHexString(32);
    const hashedToken = await bcrypt.hash(verifyToken, DotenvConfig.BcryptSalt);

    const token = await tokenRepo.save(
      tokenRepo.create({
        userId: user.id,
        token: hashedToken,
        tokenType: TokenType.EMAIL_VERIFICATION,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
      })
    );

    const verifyURL = `${DotenvConfig.frontendBaseURL}/verifyemail?id=${token.id}&token=${verifyToken}`;
    // await EmailService.sendMailTemplate('verifyEmailTemplate', user.email, { username: user.firstName, link: verifyURL });
    await mailClient.sendEmail({
      recipientEmail: user.email,
      subject: 'Verify Your Email Address',
      templateName: 'unverifiedAccount',
      placeholders: {
        first_name: user.firstName,
        verify_link: verifyURL,
      },
    });

    throw new Unauthorized(
      `Account not verified. A verification link has been sent to ${user.email}.`
    );
  }

  private static async handleDeactivatedAccount(user: IUser) {
    if (!user.isAccountActive) throw new Unauthorized('Account is deactivated');
  }

  private static async resetLoginAttempts(user: IUser) {
    user.loginAttempts = 0;
    user.lastLoginDate = new Date();
    if (user.reAuth) user.reAuth = false;
    await userRepo.save(user);
  }

  private static async generateTokens(
    user: IUser,
    rememberMe: boolean = false
  ) {
    const accessTokenPayload: TokenPayload = {
      sub: user.id,
      appRole: user.appRole,
      type: TokenType.ACCESS,
      tokenVersion: user.tokenVersion,
      rememberMe,
    };

    const refreshTokenPayload: TokenPayload = {
      sub: user.id,
      appRole: user.appRole,
      type: TokenType.REFRESH,
      tokenVersion: user.tokenVersion,
      rememberMe: false,
    };

    const accessToken = this.generateJWT(
      accessTokenPayload,
      DotenvConfig.JWTHeader.accessTokenSecret,
      DotenvConfig.TokenExpiry.accessToken
    );
    const refreshToken = this.generateJWT(
      refreshTokenPayload,
      DotenvConfig.JWTHeader.refreshTokenSecret,
      DotenvConfig.TokenExpiry.refreshToken
    );

    return { accessToken, refreshToken };
  }

  private static generateJWT(
    payload: TokenPayload,
    secret: string,
    expiresIn: SignOptions['expiresIn']
  ): string {
    return jwt.sign(payload, secret, { ...this.JWT_OPTIONS, expiresIn });
  }

  static async verifyJWT(token: string, type: TokenType): Promise<JwtPayload> {
    const secret =
      type === TokenType.REFRESH
        ? DotenvConfig.JWTHeader.refreshTokenSecret
        : DotenvConfig.JWTHeader.accessTokenSecret;

    try {
      const verifyOptions = {
        issuer: DotenvConfig.JWTHeader.issuer,
        audience: Array.isArray(DotenvConfig.JWTHeader.audience)
          ? DotenvConfig.JWTHeader.audience.length === 1
            ? DotenvConfig.JWTHeader.audience[0]
            : DotenvConfig.JWTHeader.audience
          : DotenvConfig.JWTHeader.audience,
        algorithms: [DotenvConfig.JWTHeader.algorithm],
      };
      const decoded = jwt.verify(token, secret, verifyOptions) as JwtPayload;
      return decoded;
    } catch (error: any) {
      this.handleTokenError(error);
      throw new Unauthorized('Invalid or expired token');
    }
  }

  private static handleTokenError(error: any) {
    if (error.name === 'TokenExpiredError') {
      throw new Unauthorized('Token has expired');
    } else if (error.name === 'JsonWebTokenError') {
      throw new Unauthorized('Invalid token');
    } else {
      throw new Unauthorized('Authentication failed');
    }
  }
}
