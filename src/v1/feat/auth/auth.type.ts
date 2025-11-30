import { AppRoles } from '@user/user.type';

export interface ISignin {
  email: string;
  password: string;
  rememberMe: boolean;
}

export interface ISignup {
  firstName: string;
  lastName: string;
  email: string;
  password: string;
  appRole: AppRoles;
}

export interface IVerifyEmail {
  email: string;
  otp: string;
}

export interface IPersonaliseAccount {
  email: string;
  gender: string;
  interests?: string[];
}

export interface ISetPassword {
  email: string;
  password: string;
  // confirmPassword: string;
}

export enum TokenType {
  ACCESS = 'access',
  REFRESH = 'refresh',
  EMAIL_VERIFICATION = 'Email Verification',
  RESET_PASSWORD = 'Reset Password',
}

export interface IToken {
  userId: string;
  token: string;
  tokenType: TokenType;
  createdAt: Date;
}

export interface TokenPayload {
  sub: string;
  appRole: string;
  type: TokenType;
  tokenVersion: number;
  rememberMe: boolean;
}

export interface ILoginAttempt extends Document {
  email: string;
  success: boolean;
  timestamp: Date;
  ipAddress: string;
}
