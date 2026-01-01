import * as grpc from '@grpc/grpc-js';
import { Protos } from '../index';
import DotenvConfig from '@config/dotenv.config';
import UserService from '@user/user.service';
import AuthService from '@auth/auth.service';

export default class UserServiceImpl {
  getUser = async (call: any, callback: any) => {
    try {
      const { id } = call.request;

      if (!id) {
        return callback({
          code: grpc.status.INVALID_ARGUMENT,
          message: 'User ID is required',
        });
      }

      const user = await UserService.getUserById(id);

      callback(null, {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        // phone: user.,
        isVerified: user.isVerified,
        isAccountActive: user.isAccountActive,
        lastLoginDate: user.lastLoginDate,
        loginAttempts: user.loginAttempts,
        allowedLoginAttempts: user.allowedLoginAttempts,
        loginCooldown: user.loginCooldown,
        createdAt: user.createdAt?.toISOString(),
        updatedAt: user.updatedAt?.toISOString(),
      });
    } catch (error: any) {
      console.error('gRPC Error - getUser:', error);
      switch (error.name) {
        case 'InvalidInput':
          callback({
            code: grpc.status.INVALID_ARGUMENT,
            message: error.message,
          });
          break;
        case 'ResourceNotFound':
          callback({
            code: grpc.status.NOT_FOUND,
            message: error.message,
          });
          break;

        default:
          callback({
            code: grpc.status.INTERNAL,
            message: 'Internal server error',
          });
          break;
      }
    }
  };

  getUserEmail = async (call: any, callback: any) => {
    try {
      const { email } = call.request;
      if (!email) {
        return callback({
          code: grpc.status.INVALID_ARGUMENT,
          message: 'Email is required',
        });
      }

      const user = await UserService.getUserByEmail(email);
      callback(null, {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        createdAt: user.createdAt?.toISOString(),
        updatedAt: user.updatedAt?.toISOString(),
      });
    } catch (error: any) {
      console.error('gRPC Error - getUser:', error);
      switch (error.name) {
        case 'InvalidInput':
          callback({
            code: grpc.status.INVALID_ARGUMENT,
            message: error.message,
          });
          break;
        case 'ResourceNotFound':
          callback({
            code: grpc.status.NOT_FOUND,
            message: error.message,
          });
          break;

        default:
          callback({
            code: grpc.status.INTERNAL,
            message: 'Internal server error',
          });
          break;
      }
    }
  };

  signin = async (call: any, callback: any) => {
    try {
      const { email, password } = call.request;

      if (!email || !password) {
        return callback({
          code: grpc.status.INVALID_ARGUMENT,
          message: 'Email and password are required',
        });
      }

      // Get client IP from gRPC call metadata
      const peer = call.getPeer() || '';
      const ipAddress = peer.split(':')[0] || 'unknown';

      const result = await AuthService.signin(
        { email, password, rememberMe: false },
        ipAddress
      );

      callback(null, {
        success: true,
        user: {
          userId: result.user.id,
          firstName: result.user.firstName,
          lastName: result.user.lastName,
          email: result.user.email,
          phone: '',
          isVerified: result.user.isVerified,
          isAccountActive: result.user.isAccountActive,
          lastLoginDate: result.user.lastLoginDate,
          loginAttempts: result.user.loginAttempts,
          allowedLoginAttempts: result.user.allowedLoginAttempts,
          loginCooldown: result.user.loginCooldown,
          createdAt: result.user.createdAt?.toISOString(),
          updatedAt: result.user.updatedAt?.toISOString(),
        },
        error: '',
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
      });
    } catch (error: any) {
      console.error('gRPC Error - signin:', error);

      // Return structured error response instead of gRPC error
      // This allows the gateway to handle the response gracefully
      callback(null, {
        success: false,
        user: null,
        error: error.message || 'Invalid credentials',
      });
    }
  };

  signup = async (call: any, callback: any) => {
    try {
      const { firstName, lastName, email, password, appRole } = call.request;

      if (!firstName || !lastName || !email || !password) {
        return callback(null, {
          success: false,
          userId: '',
          message: '',
          error: 'All fields are required',
        });
      }

      // Get client IP from gRPC call metadata
      const peer = call.getPeer() || '';
      const ipAddress = peer.split(':')[0] || 'unknown';

      const user = await AuthService.signup(
        { firstName, lastName, email, password, appRole: appRole || 'buyer' },
        ipAddress
      );

      callback(null, {
        success: true,
        userId: user.id,
        message:
          'Account created successfully. Please check your email for verification code.',
        error: '',
      });
    } catch (error: any) {
      console.error('gRPC Error - signup:', error);

      callback(null, {
        success: false,
        userId: '',
        message: '',
        error: error.message || 'Failed to create account',
      });
    }
  };

  verifyOTP = async (call: any, callback: any) => {
    try {
      const { email, otp } = call.request;

      if (!email || !otp) {
        return callback(null, {
          success: false,
          message: '',
          error: 'Email and OTP are required',
        });
      }

      const peer = call.getPeer() || '';
      const ipAddress = peer.split(':')[0] || 'unknown';

      await AuthService.verifyOTP(email, otp, ipAddress);

      callback(null, {
        success: true,
        message: 'Email verified successfully',
        error: '',
      });
    } catch (error: any) {
      console.error('gRPC Error - verifyOTP:', error);

      callback(null, {
        success: false,
        message: '',
        error: error.message || 'Invalid or expired OTP',
      });
    }
  };

  resendOTP = async (call: any, callback: any) => {
    try {
      const { email } = call.request;

      if (!email) {
        return callback(null, {
          success: false,
          message: '',
          error: 'Email is required',
        });
      }

      const peer = call.getPeer() || '';
      const ipAddress = peer.split(':')[0] || 'unknown';

      await AuthService.resendOTP(email, ipAddress);

      callback(null, {
        success: true,
        message: 'Verification code sent to your email',
        error: '',
      });
    } catch (error: any) {
      console.error('gRPC Error - resendOTP:', error);

      callback(null, {
        success: false,
        message: '',
        error: error.message || 'Failed to resend OTP',
      });
    }
  };
}
