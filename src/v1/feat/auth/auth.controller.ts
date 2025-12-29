import { Request, Response, NextFunction } from 'express';
import { Unauthorized } from '@middlewares/error.middleware';
import AuthService from './auth.service';
import { extractClientInfo } from '@utils/request.utils';

export default class AuthController {
  static async signup(req: Request, res: Response, next: NextFunction) {
    try {
      const { ipAddress, userAgent, location } = extractClientInfo(req);

      await AuthService.signup(req.body, ipAddress, userAgent, location);

      res.setHeader('Access-Control-Allow-Credentials', 'true');

      res.status(201).json({
        success: true,
        message:
          'User created successfully. A verification email has been sent to your email address. ',
      });
    } catch (error) {
      next(error);
    }
  }

  static async verifyOTP(req: Request, res: Response, next: NextFunction) {
    try {
      let { email, otp } = req.body;

      const { ipAddress, userAgent, location } = extractClientInfo(req);

      await AuthService.verifyOTP(
        email as string,
        otp as string,
        ipAddress,
        userAgent,
        location
      );

      res.status(200).json({
        success: true,
        message: 'Email verified successfully',
      });
    } catch (error) {
      next(error);
    }
  }

  static async resendOTP(req: Request, res: Response, next: NextFunction) {
    try {
      let { email } = req.body;
      const { ipAddress, userAgent, location } = extractClientInfo(req);
      if (!email) {
        throw new Unauthorized('Email is required');
      }

      await AuthService.resendOTP(email, ipAddress, userAgent, location);
      res.status(200).json({
        success: true,
        message: 'Resent OTP sent successfully',
      });
    } catch (error) {
      next(error);
    }
  }

  static async signin(req: Request, res: Response, next: NextFunction) {
    try {
      let { email, password, rememberMe } = req.body;
      const { ipAddress, userAgent, location } = extractClientInfo(req);

      const { accessToken, refreshToken, user, device } =
        await AuthService.signin(
          {
            email,
            password,
            rememberMe,
          },
          ipAddress!,
          userAgent,
          location
        );

      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('at', accessToken);
      res.setHeader('rt', refreshToken);

      res.status(200).json({
        success: true,
        message: 'Signin successful',
        data: {
          accessToken,
          refreshToken,
          user: {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            appRole: user.appRole,
            isVerified: user.isVerified,
          },
          device: {
            deviceId: device.deviceId,
            deviceType: device.deviceType,
            location: device.location,
            isTrusted: device.isTrusted,
            lastActive: device.lastActive,
          },
        },
      });
    } catch (error) {
      console.log(error);
      next(error);
    }
  }

  static async forgotPassword(req: Request, res: Response, next: NextFunction) {
    try {
      const { email } = req.body;

      await AuthService.forgotPassword(email);

      // Response is sent before the email is sent to avoid timing attacks
      res.status(200).json({
        success: true,
        message:
          'If that email address is in our database, we will send you an email to reset your password.',
      });
    } catch (error) {
      next(error);
    }
  }
}
