import * as grpc from '@grpc/grpc-js';
import DotenvConfig from '@config/dotenv.config';
import UserService from '@user/user.service';
import AuthService from '@auth/auth.service';
import DeviceService from '@security/device.service';
import ActivityService from '@security/activity.service';
import { Event } from '@security/activity.type';
import { TokenType } from '@auth/auth.type';
import { withGrpcErrorHandler } from '../grpc-error.handler';
import {
  BadRequest,
  InvalidInput,
} from '@middlewares/error.middleware';

export default class UserServiceImpl {
  getUser = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { userId } = call.request;

    if (!userId) {
      throw new BadRequest('User ID is required');
    }

    const user = await UserService.getUserById(userId);

    callback(null, {
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      isVerified: user.isVerified,
      isAccountActive: user.isAccountActive,
      lastLoginDate: user.lastLoginDate,
      loginAttempts: user.loginAttempts,
      allowedLoginAttempts: user.allowedLoginAttempts,
      loginCooldown: user.loginCooldown,
      createdAt: user.createdAt?.toISOString(),
      updatedAt: user.updatedAt?.toISOString(),
    });
  });

  getUserEmail = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { email } = call.request;

    if (!email) {
      throw new BadRequest('Email is required');
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
  });

  signin = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { email, password } = call.request;

    if (!email || !password) {
      throw new BadRequest('Email and password are required');
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
  });

  signup = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { firstName, lastName, email, password, appRole } = call.request;

    if (!firstName || !lastName || !email || !password) {
      throw new BadRequest('All fields are required');
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
  });

  verifyOTP = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { email, otp } = call.request;

    if (!email || !otp) {
      throw new BadRequest('Email and OTP are required');
    }

    const peer = call.getPeer() || '';
    const ipAddress = peer.split(':')[0] || 'unknown';

    await AuthService.verifyOTP(email, otp, ipAddress);

    callback(null, {
      success: true,
      message: 'Email verified successfully',
      error: '',
    });
  });

  resendOTP = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { email } = call.request;

    if (!email) {
      throw new BadRequest('Email is required');
    }

    const peer = call.getPeer() || '';
    const ipAddress = peer.split(':')[0] || 'unknown';

    await AuthService.resendOTP(email, ipAddress);

    callback(null, {
      success: true,
      message: 'Verification code sent to your email',
      error: '',
    });
  });

  // ==================== Security & Device Management ====================

  /**
   * Validate access token - called by API Gateway for authentication
   */
  validateToken = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { accessToken } = call.request;

    if (!accessToken) {
      throw new BadRequest('Access token is required');
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
  });

  /**
   * Register or update device for a user
   */
  registerDevice = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { userId, ipAddress, userAgent, isTrusted } = call.request;

    if (!userId) {
      throw new BadRequest('User ID is required');
    }

    // Validate IP address format if provided
    if (ipAddress && !this.isValidIpAddress(ipAddress)) {
      throw new InvalidInput('Invalid IP address format');
    }

    // Register or update the device
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
  });

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
  logActivity = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { event, userId, ipAddress, userAgent, deviceId, metadata } =
      call.request;

    if (!event) {
      throw new BadRequest('Event type is required');
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
  });

  /**
   * Check if a device is trusted for sensitive operations
   */
  checkDeviceTrust = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { userId, deviceId } = call.request;

    if (!userId || !deviceId) {
      throw new BadRequest('User ID and Device ID are required');
    }

    const isTrusted = await DeviceService.isDeviceTrusted(userId, deviceId);

    callback(null, { isTrusted });
  });
}
