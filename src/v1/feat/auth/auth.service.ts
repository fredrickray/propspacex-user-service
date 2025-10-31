import bcrypt from 'bcrypt';
import jwt, { SignOptions, JwtPayload } from 'jsonwebtoken';
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
import { AppDataSource } from '@config/data.source';
import { User } from '@user/user.entity';
import { LoginAttempt, Token } from './auth.entity';

const userRepo = AppDataSource.getRepository(User);
const loginAttemptRepo = AppDataSource.getRepository(LoginAttempt);
const tokenRepo = AppDataSource.getRepository(Token);

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

  static async signup(payload: ISignup) {
    const exisitingUser = await userRepo.findOneBy({ email: payload.email });
    if (exisitingUser) throw new BadRequest('Email already exists');

    const hashedPassword = await this.hashPassword(payload.password);

    const newUser = userRepo.create({
      firstName: payload.firstName,
      lastName: payload.lastName,
      email: payload.email,
      password: hashedPassword,
      appRole: payload.appRole,
    });

    await userRepo.save(newUser);

    return newUser;
  }

  static async signin(payload: ISignin, ipAddress: string) {
    const user = await userRepo.findOneBy({ email: payload.email });
    if (!user) {
      this.logFailedAttempt(payload.email, ipAddress);
      throw new ResourceNotFound('Invalid credentials');
    }

    this.checkLoginCooldown(user, ipAddress);

    const isPasswordValid = await bcrypt.compare(
      payload.password,
      user.password
    );
    if (!isPasswordValid) {
      await this.handleInvalidPassword(user, payload.email, ipAddress);
    }

    if (!user.isVerified) await this.handleUnverifiedAccount(user);

    if (!user.isVerified) await this.handleUnverifiedAccount(user);

    await this.resetLoginAttempts(user);

    // const tokens = await this.generateTokens(user);
    const { accessToken, refreshToken } = await this.generateTokens(user);
    return { accessToken, refreshToken, user };
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
    ipAddress: string
  ) {
    user.loginAttempts += 1;

    if (user.loginAttempts >= user.allowedLoginAttempts) {
      user.loginCooldown = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
      user.loginAttempts = 0;

      await userRepo.save(user);
      throw new TooManyRequests(
        `Account locked due to multiple failed login attempts. Try again after ${user.loginCooldown}`
      );
    }

    await userRepo.save(user);
    this.logFailedAttempt(email, ipAddress);
    throw new Unauthorized(
      `Invalid credentials. ${user.allowedLoginAttempts - user.loginAttempts} attempt(s) remaining`
    );
  }

  private static async handleUnverifiedAccount(user: IUser) {
    const verifyToken = generateRandomHexString(32);
    const hashedToken = await bcrypt.hash(verifyToken, DotenvConfig.BcryptSalt);

    const token = tokenRepo.create({
      userId: user.id,
      token: hashedToken,
      tokenType: TokenType.EMAIL_VERIFICATION,
    });

    // const verifyURL = `${DotenvConfig.frontendBaseURL}/verifyemail?id=${token._id}&token=${verifyToken}`;
    // await EmailService.sendMailTemplate('verifyEmailTemplate', user.email, { username: user.firstName, link: verifyURL });

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

  private static async generateTokens(user: any) {
    const accessTokenPayload: TokenPayload = {
      sub: user.id,
      appRole: user.appRole,
      iat: Date.now(),
      exp: Date.now() + DotenvConfig.TokenExpiry.accessToken,
      type: TokenType.ACCESS,
      rememberMe: false,
    };

    const refreshTokenPayload: TokenPayload = {
      sub: user.id,
      appRole: user.appRole,
      iat: Date.now(),
      exp: Date.now() + DotenvConfig.TokenExpiry.refreshToken,
      type: TokenType.REFRESH,
      rememberMe: false,
    };

    const accessToken = this.generateJWT(
      accessTokenPayload,
      DotenvConfig.JWTHeader.accessTokenSecret
    );
    const refreshToken = this.generateJWT(
      refreshTokenPayload,
      DotenvConfig.JWTHeader.refreshTokenSecret
    );

    return { accessToken, refreshToken };
  }

  private static generateJWT(payload: TokenPayload, secret: string): string {
    return jwt.sign(payload, secret, this.JWT_OPTIONS);
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
