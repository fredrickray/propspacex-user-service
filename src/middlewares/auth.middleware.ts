import { Request, Response, NextFunction } from 'express';
import { Forbidden, ResourceNotFound, Unauthorized } from './error.middleware';
import { TokenType } from '@auth/auth.type';
import AuthService from '@auth/auth.service';
import { AppDataSource } from '@config/data.source';
import { User } from '@user/user.entity';
import { AppRoles, IUser } from '@user/user.type';
import DeviceService from '@security/device.service';

const userRepo = AppDataSource.getRepository(User);

declare global {
  namespace Express {
    interface Request {
      authUser?: IUser;
      deviceId?: string;
      ipAddress?: string;
      userAgent?: string;
    }
  }
}

export class AuthMiddleware {
  private static extractAccessToken(req: Request): string | null {
    // Authorization header (Bearer token)
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.split(' ')[1];
    }

    // HTTP-only cookie
    if ((req as any).cookies?.access_token) {
      return (req as any).cookies.access_token;
    }

    // Legacy header (optional)
    if (req.headers['at']) {
      return req.headers['at'] as string;
    }

    return null;
  }

  private static extractRefreshToken(req: Request): string | null {
    // HTTP-only cookie (preferred)
    if ((req as any).cookies?.refresh_token) {
      return (req as any).cookies.refresh_token;
    }

    // Header fallback
    if (req.headers['x-refresh-token']) {
      return req.headers['x-refresh-token'] as string;
    }

    return null;
  }

  private static extractIpAddress(req: Request): string {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
      const ips = Array.isArray(forwarded)
        ? forwarded[0]
        : forwarded.split(',')[0];
      return ips.trim();
    }
    return req.ip || req.socket.remoteAddress || 'unknown';
  }

  private static extractUserAgent(req: Request): string {
    return req.headers['user-agent'] || 'unknown';
  }

  static async authorizeUser(req: Request, res: Response, next: NextFunction) {
    try {
      const accessToken = AuthMiddleware.extractAccessToken(req);
      if (!accessToken) {
        throw new Unauthorized('Authorization token required');
      }

      const decoded = await AuthService.verifyJWT(
        accessToken,
        TokenType.ACCESS
      );

      const userId = decoded.sub as string;

      const existingUser = await userRepo.findOneBy({ id: userId });
      if (!existingUser) throw new ResourceNotFound('User not found');

      // Check if user requires re-authentication
      if ((existingUser as any).reAuth)
        throw new Unauthorized('Access denied, please re-authenticate');

      // Check if account is active
      if (!existingUser.isAccountActive) {
        throw new Unauthorized(
          'Your account is deactivated. Please contact support.'
        );
      }

      // Check if account is verified
      if (!existingUser.isVerified) {
        throw new Unauthorized('Please verify your email address');
      }

      // Attach user and request metadata
      req.authUser = existingUser as IUser;
      req.ipAddress = AuthMiddleware.extractIpAddress(req);
      req.userAgent = AuthMiddleware.extractUserAgent(req);

      next();
    } catch (error) {
      next(error);
    }
  }

  /**
   * Optional authentication - attaches user if token present, but doesn't require it
   */
  static async optionalAuth(req: Request, res: Response, next: NextFunction) {
    try {
      const accessToken = AuthMiddleware.extractAccessToken(req);

      if (!accessToken) {
        req.ipAddress = AuthMiddleware.extractIpAddress(req);
        req.userAgent = AuthMiddleware.extractUserAgent(req);
        return next();
      }

      const decoded = await AuthService.verifyJWT(
        accessToken,
        TokenType.ACCESS
      );
      const userId = decoded.sub as string;

      const existingUser = await userRepo.findOneBy({ id: userId });
      if (existingUser && existingUser.isAccountActive) {
        req.authUser = existingUser as IUser;
      }

      req.ipAddress = AuthMiddleware.extractIpAddress(req);
      req.userAgent = AuthMiddleware.extractUserAgent(req);

      next();
    } catch (error) {
      // Silently fail for optional auth - just continue without user
      req.ipAddress = AuthMiddleware.extractIpAddress(req);
      req.userAgent = AuthMiddleware.extractUserAgent(req);
      next();
    }
  }

  /**
   * Role-based authorization middleware factory
   * @param allowedRoles - Array of roles that can access the route
   */
  static authorizeRoles(...allowedRoles: AppRoles[]) {
    return async (req: Request, res: Response, next: NextFunction) => {
      try {
        if (!req.authUser) {
          throw new Unauthorized('Authentication required');
        }

        const userRole = req.authUser.appRole;

        // Admin bypass - admins can access everything
        if (userRole === AppRoles.ADMIN) {
          return next();
        }

        if (!allowedRoles.includes(userRole)) {
          throw new Forbidden(
            'You do not have permission to access this resource'
          );
        }

        next();
      } catch (error) {
        next(error);
      }
    };
  }

  /**
   * Admin-only middleware
   */
  static async adminOnly(req: Request, res: Response, next: NextFunction) {
    try {
      if (!req.authUser) {
        throw new Unauthorized('Authentication required');
      }

      if (req.authUser.appRole !== AppRoles.ADMIN) {
        throw new Forbidden('Admin access required');
      }

      next();
    } catch (error) {
      next(error);
    }
  }

  /**
   * Verify the current user owns the resource or is an admin
   * @param paramKey - The request parameter key containing the user ID to check
   */
  static ownerOrAdmin(paramKey: string = 'userId') {
    return async (req: Request, res: Response, next: NextFunction) => {
      try {
        if (!req.authUser) {
          throw new Unauthorized('Authentication required');
        }

        const resourceOwnerId = req.params[paramKey];

        // Admin bypass
        if (req.authUser.appRole === AppRoles.ADMIN) {
          return next();
        }

        // Check if user owns the resource
        if (req.authUser.id !== resourceOwnerId) {
          throw new Forbidden(
            'You do not have permission to access this resource'
          );
        }

        next();
      } catch (error) {
        next(error);
      }
    };
  }

  /**
   * Require a trusted device for sensitive operations
   */
  static async requireTrustedDevice(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    try {
      if (!req.authUser) {
        throw new Unauthorized('Authentication required');
      }

      const deviceId = req.headers['x-device-id'] as string;
      if (!deviceId) {
        throw new Unauthorized('Device identification required');
      }

      const isTrusted = await DeviceService.isDeviceTrusted(
        req.authUser.id,
        deviceId
      );

      if (!isTrusted) {
        throw new Forbidden(
          'This action requires a trusted device. Please verify your device first.'
        );
      }

      req.deviceId = deviceId;
      next();
    } catch (error) {
      next(error);
    }
  }

  /**
   * Verify refresh token middleware - used for token refresh endpoints
   */
  static async verifyRefreshToken(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    try {
      const refreshToken = AuthMiddleware.extractRefreshToken(req);
      if (!refreshToken) {
        throw new Unauthorized('Refresh token required');
      }

      const decoded = await AuthService.verifyJWT(
        refreshToken,
        TokenType.REFRESH
      );

      const userId = decoded.sub as string;

      const existingUser = await userRepo.findOneBy({ id: userId });
      if (!existingUser) {
        throw new ResourceNotFound('User not found');
      }

      if (!existingUser.isAccountActive) {
        throw new Unauthorized('Your account is deactivated');
      }

      req.authUser = existingUser as IUser;
      req.ipAddress = AuthMiddleware.extractIpAddress(req);
      req.userAgent = AuthMiddleware.extractUserAgent(req);

      next();
    } catch (error) {
      next(error);
    }
  }

  /**
   * Attach request metadata (IP, user agent) without authentication
   */
  static attachRequestMetadata(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    req.ipAddress = AuthMiddleware.extractIpAddress(req);
    req.userAgent = AuthMiddleware.extractUserAgent(req);
    next();
  }

  /**
   * Check if account is verified
   */
  static async requireVerifiedAccount(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    try {
      if (!req.authUser) {
        throw new Unauthorized('Authentication required');
      }

      if (!req.authUser.isVerified) {
        throw new Forbidden(
          'Please verify your email address to access this feature'
        );
      }

      next();
    } catch (error) {
      next(error);
    }
  }
}

// Export individual middleware functions for convenience
export const authorizeUser = AuthMiddleware.authorizeUser.bind(AuthMiddleware);
export const optionalAuth = AuthMiddleware.optionalAuth.bind(AuthMiddleware);
export const authorizeRoles =
  AuthMiddleware.authorizeRoles.bind(AuthMiddleware);
export const adminOnly = AuthMiddleware.adminOnly.bind(AuthMiddleware);
export const ownerOrAdmin = AuthMiddleware.ownerOrAdmin.bind(AuthMiddleware);
export const requireTrustedDevice =
  AuthMiddleware.requireTrustedDevice.bind(AuthMiddleware);
export const verifyRefreshToken =
  AuthMiddleware.verifyRefreshToken.bind(AuthMiddleware);
export const attachRequestMetadata =
  AuthMiddleware.attachRequestMetadata.bind(AuthMiddleware);
export const requireVerifiedAccount =
  AuthMiddleware.requireVerifiedAccount.bind(AuthMiddleware);
