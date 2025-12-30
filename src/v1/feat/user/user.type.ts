export enum AppRoles {
  ADMIN = 'admin',
  BUYER = 'buyer',
  AGENT = 'agent',
}

export enum UserStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  BANNED = 'banned',
  PENDING = 'pending',
}

export interface IUser {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  password: string;
  appRole: AppRoles;
  reAuth?: boolean;
  tokenVersion: number;
  isVerified: boolean;
  isAccountActive: boolean;
  lastLoginDate: Date;
  loginAttempts: number;
  allowedLoginAttempts: number;
  loginCooldown: Date;
  createdAt: Date;
}
