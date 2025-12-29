import { User } from '@user/user.entity';
import { Device } from './device.entity';
import { AppDataSource } from '@config/data.source';
import ActivityService from './activity.service';
import { Event } from './activity.type';
import { getMailClient } from '@grpc/client/mail.client';

const userRepo = AppDataSource.getRepository(User);
const mailClient = getMailClient();

export interface SecurityAlertContext {
  userId: string;
  alertType: SecurityAlertType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  metadata?: Record<string, any>;
}

export enum SecurityAlertType {
  NEW_DEVICE = 'NEW_DEVICE',
  NEW_LOCATION = 'NEW_LOCATION',
  FAILED_LOGIN_ATTEMPTS = 'FAILED_LOGIN_ATTEMPTS',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  PASSWORD_CHANGED = 'PASSWORD_CHANGED',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',
}

export default class SecurityAlertService {
  static async sendNewDeviceAlert(userId: string, device: Device) {
    const user = await userRepo.findOne({ where: { id: userId } });
    if (!user) return;

    try {
      await mailClient.sendLoginAlertEmail({
        recipientEmail: user.email,
        firstName: user.firstName,
        loginTime: new Date().toISOString(),
        ipAddress: device.ipAddress || 'Unknown',
        deviceInfo: device.userAgent || 'Unknown device',
        location: device.location || 'Unknown',
        isNewDevice: true,
      });
    } catch (error) {
      console.error('Failed to send new device alert email:', error);
    }

    await ActivityService.log(Event.SUSPICIOUS_ACTIVITY, {
      userId,
      ip: device.ipAddress || undefined,
      userAgent: device.userAgent || undefined,
      location: device.location || undefined,
      metadata: {
        alertType: SecurityAlertType.NEW_DEVICE,
        deviceId: device.deviceId,
      },
    });
  }

  static async sendFailedLoginAlert(
    userId: string,
    attemptsCount: number,
    ipAddress?: string,
    location?: string
  ) {
    const user = await userRepo.findOne({ where: { id: userId } });
    if (!user) return;

    try {
      await mailClient.sendNotificationEmail({
        recipientEmail: user.email,
        firstName: user.firstName,
        subject: 'Multiple Failed Login Attempts Detected',
        title: 'Failed Login Attempts',
        message: `We detected ${attemptsCount} failed login attempt(s) on your account from IP: ${ipAddress || 'Unknown'}, Location: ${location || 'Unknown'}. If this wasn't you, please secure your account immediately.`,
        notificationType: attemptsCount >= 3 ? 'warning' : 'info',
      });
    } catch (error) {
      console.error('Failed to send failed login alert email:', error);
    }
  }

  static async sendAccountLockedAlert(
    userId: string,
    cooldownUntil: Date,
    ipAddress?: string,
    location?: string
  ) {
    const user = await userRepo.findOne({ where: { id: userId } });
    if (!user) return;

    try {
      await mailClient.sendNotificationEmail({
        recipientEmail: user.email,
        firstName: user.firstName,
        subject: 'Your Account Has Been Locked',
        title: 'Account Locked',
        message: `Your account has been temporarily locked due to multiple failed login attempts. You can try again after ${cooldownUntil.toLocaleString()}. IP: ${ipAddress || 'Unknown'}, Location: ${location || 'Unknown'}. If you didn't attempt to log in, please contact support immediately.`,
        notificationType: 'error',
      });
    } catch (error) {
      console.error('Failed to send account locked alert email:', error);
    }
  }

  static async sendPasswordChangedAlert(
    userId: string,
    ipAddress?: string,
    location?: string
  ) {
    const user = await userRepo.findOne({ where: { id: userId } });
    if (!user) return;

    try {
      await mailClient.sendPasswordChangedEmail({
        recipientEmail: user.email,
        firstName: user.firstName,
        changedAt: new Date().toISOString(),
        ipAddress: ipAddress || 'Unknown',
        deviceInfo: 'N/A',
        location: location || 'Unknown',
      });
    } catch (error) {
      console.error('Failed to send password changed alert email:', error);
    }
  }

  static async sendSuspiciousActivityAlert(
    userId: string,
    reason: string,
    metadata?: Record<string, any>
  ) {
    const user = await userRepo.findOne({ where: { id: userId } });
    if (!user) return;

    try {
      await mailClient.sendNotificationEmail({
        recipientEmail: user.email,
        firstName: user.firstName,
        subject: 'Suspicious Activity Detected',
        title: 'Suspicious Activity',
        message: `We detected suspicious activity on your account. Reason: ${reason}. Please review your recent account activity and secure your account if necessary.`,
        notificationType: 'warning',
      });
    } catch (error) {
      console.error('Failed to send suspicious activity alert email:', error);
    }
  }

  static async sendNewLocationAlert(
    userId: string,
    newLocation: string,
    ipAddress?: string,
    deviceInfo?: string
  ) {
    const user = await userRepo.findOne({ where: { id: userId } });
    if (!user) return;

    try {
      await mailClient.sendLoginAlertEmail({
        recipientEmail: user.email,
        firstName: user.firstName,
        loginTime: new Date().toISOString(),
        ipAddress: ipAddress || 'Unknown',
        deviceInfo: deviceInfo || 'Unknown device',
        location: newLocation,
        isNewDevice: false,
      });
    } catch (error) {
      console.error('Failed to send new location alert email:', error);
    }

    await ActivityService.log(Event.SUSPICIOUS_ACTIVITY, {
      userId,
      ip: ipAddress,
      location: newLocation,
      metadata: {
        alertType: SecurityAlertType.NEW_LOCATION,
      },
    });
  }
}
