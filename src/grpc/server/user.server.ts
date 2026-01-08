import * as grpc from '@grpc/grpc-js';
import { Protos } from '../index';
import DotenvConfig from '@config/dotenv.config';
import UserService from '@user/user.service';
import AuthService from '@auth/auth.service';
import DeviceService from '@security/device.service';
import ActivityService from '@security/activity.service';
import { Event } from '@security/activity.type';
import { TokenType } from '@auth/auth.type';

export default class UserServiceImpl {
  getUser = async (call: any, callback: any) => {
    try {
      const { userId } = call.request;

      if (!userId) {
        return callback({
          code: grpc.status.INVALID_ARGUMENT,
          message: 'User ID is required',
        });
      }

      const user = await UserService.getUserById(userId);

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

  // ==================== Security & Device Management ====================

  /**
   * Validate access token - called by API Gateway for authentication
   */
  validateToken = async (call: any, callback: any) => {
    try {
      const { accessToken } = call.request;

      if (!accessToken) {
        return callback(null, {
          valid: false,
          userId: '',
          email: '',
          appRole: '',
          isVerified: false,
          isAccountActive: false,
          error: 'Access token is required',
        });
      }

      // Verify the JWT token
      const decoded = await AuthService.verifyJWT(
        accessToken,
        TokenType.ACCESS
      );
      const userId = decoded.sub as string;

      // Get user from database
      const user = await UserService.getUserById(userId);

      callback(null, {
        valid: true,
        userId: user.id,
        email: user.email,
        appRole: user.appRole || 'buyer',
        isVerified: user.isVerified,
        isAccountActive: user.isAccountActive,
        error: '',
      });
    } catch (error: any) {
      console.error('gRPC Error - validateToken:', error);

      callback(null, {
        valid: false,
        userId: '',
        email: '',
        appRole: '',
        isVerified: false,
        isAccountActive: false,
        error: 'Invalid or expired token',
      });
    }
  };

  /**
   * Register or update device for a user
   */
  registerDevice = async (call: any, callback: any) => {
    try {
      const { userId, ipAddress, userAgent, isTrusted } = call.request;

      if (!userId) {
        return callback(null, {
          success: false,
          deviceId: '',
          isNewDevice: false,
          isSuspicious: false,
          error: 'User ID is required',
        });
      }

      // Validate IP address format if provided
      if (ipAddress && !this.isValidIpAddress(ipAddress)) {
        return callback(null, {
          success: false,
          deviceId: '',
          isNewDevice: false,
          isSuspicious: false,
          error: 'Invalid IP address format',
        });
      }

      // Register or update the device (DeviceService handles suspicious activity detection internally)
      const { device, isNewDevice, isSuspicious } =
        await DeviceService.registerOrUpdate(userId, ipAddress, userAgent, {
          isTrusted: isTrusted || false,
        });

      callback(null, {
        success: true,
        deviceId: device.deviceId,
        isNewDevice,
        isSuspicious,
        error: '',
      });
    } catch (error: any) {
      console.error('gRPC Error - registerDevice:', error);

      callback(null, {
        success: false,
        deviceId: '',
        isNewDevice: false,
        isSuspicious: false,
        error: 'Failed to register device',
      });
    }
  };

  /**
   * Validate IP address format (IPv4 or IPv6)
   */
  private isValidIpAddress(ip: string): boolean {
    // IPv4 pattern
    const ipv4Pattern =
      /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    // IPv6 pattern (simplified)
    const ipv6Pattern = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
    // Also allow 'unknown' as it's used when IP can't be determined
    if (ip === 'unknown') return true;
    return ipv4Pattern.test(ip) || ipv6Pattern.test(ip);
  }

  /**
   * Log user activity for audit trail
   */
  logActivity = async (call: any, callback: any) => {
    try {
      const { event, userId, ipAddress, userAgent, deviceId, metadata } =
        call.request;

      if (!event) {
        return callback(null, { success: false });
      }

      // Parse metadata if provided
      let parsedMetadata: Record<string, any> | null = null;
      if (metadata) {
        try {
          parsedMetadata = JSON.parse(metadata);
        } catch {
          parsedMetadata = { raw: metadata };
        }
      }

      // Map string event to Event enum or use as custom event
      const eventType = (Event as any)[event];
      if (!eventType) {
        console.warn(
          `gRPC Warning - logActivity: Unrecognized event type '${event}', using as custom event`
        );
      }

      await ActivityService.log(eventType || event, {
        userId: userId || null,
        ip: ipAddress || null,
        userAgent: userAgent || null,
        deviceId: deviceId || null,
        metadata: parsedMetadata,
      });

      callback(null, { success: true, error: '' });
    } catch (error: any) {
      console.error('gRPC Error - logActivity:', error);
      callback(null, { success: false, error: 'Failed to log activity' });
    }
  };

  /**
   * Check if a device is trusted for sensitive operations
   */
  checkDeviceTrust = async (call: any, callback: any) => {
    try {
      const { userId, deviceId } = call.request;

      if (!userId || !deviceId) {
        return callback(null, { isTrusted: false });
      }

      const isTrusted = await DeviceService.isDeviceTrusted(userId, deviceId);

      callback(null, { isTrusted });
    } catch (error: any) {
      console.error('gRPC Error - checkDeviceTrust:', error);
      callback(null, { isTrusted: false });
    }
  };
}
