import * as grpc from '@grpc/grpc-js';
import { Protos } from '../index';
import DotenvConfig from '@config/dotenv.config';
import UserService from '@user/user.service';

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
}
