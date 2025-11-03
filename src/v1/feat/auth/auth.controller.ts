import { Request, Response, NextFunction } from 'express';
import { Unauthorized } from '@middlewares/error.middleware';
import AuthService from './auth.service';
export default class AuthController {
  static async signup(req: Request, res: Response, next: NextFunction) {
    try {
      const payload = req.body;

      await AuthService.signup(payload);

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

      await AuthService.verifyOTP(email as string, otp as string);

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
      if (!email) {
        throw new Unauthorized('Email is required');
      }

      await AuthService.resendOTP(email);
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
      let { email, password, rememberMe, deviceToken, deviceType } = req.body;

      const { accessToken, refreshToken, user } = await AuthService.signin(
        {
          email,
          password,
          rememberMe,
        },
        req.ip as string
      );

      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('at', accessToken);
      res.setHeader('rt', refreshToken);

      res.status(200).json({
        success: true,
        message: 'Signin successful',
        accessToken,
        refreshToken,
        user,
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
