import { User } from '@user/user.entity';
import { Device } from './device.entity';
import { AppDataSource } from '@config/data.source';
import ActivityService from './activity.service';
import { Event } from './activity.type';

const userRepo = AppDataSource.getRepository(User);

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

    const alertContext: SecurityAlertContext = {
      userId,
      alertType: SecurityAlertType.NEW_DEVICE,
      severity: 'medium',
      metadata: {
        deviceType: device.deviceType,
        location: device.location,
        ipAddress: device.ipAddress,
        timestamp: new Date(),
      },
    };

    await this.sendEmailAlert(user, alertContext);

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

    const alertContext: SecurityAlertContext = {
      userId,
      alertType: SecurityAlertType.FAILED_LOGIN_ATTEMPTS,
      severity: attemptsCount >= 3 ? 'high' : 'medium',
      metadata: {
        attemptsCount,
        ipAddress,
        location,
        timestamp: new Date(),
      },
    };

    await this.sendEmailAlert(user, alertContext);
  }

  static async sendAccountLockedAlert(
    userId: string,
    cooldownUntil: Date,
    ipAddress?: string,
    location?: string
  ) {
    const user = await userRepo.findOne({ where: { id: userId } });
    if (!user) return;

    const alertContext: SecurityAlertContext = {
      userId,
      alertType: SecurityAlertType.ACCOUNT_LOCKED,
      severity: 'critical',
      metadata: {
        cooldownUntil,
        ipAddress,
        location,
        timestamp: new Date(),
      },
    };

    await this.sendEmailAlert(user, alertContext);
  }

  static async sendPasswordChangedAlert(
    userId: string,
    ipAddress?: string,
    location?: string
  ) {
    const user = await userRepo.findOne({ where: { id: userId } });
    if (!user) return;

    const alertContext: SecurityAlertContext = {
      userId,
      alertType: SecurityAlertType.PASSWORD_CHANGED,
      severity: 'high',
      metadata: {
        ipAddress,
        location,
        timestamp: new Date(),
      },
    };

    await this.sendEmailAlert(user, alertContext);
  }

  static async sendSuspiciousActivityAlert(
    userId: string,
    reason: string,
    metadata?: Record<string, any>
  ) {
    const user = await userRepo.findOne({ where: { id: userId } });
    if (!user) return;

    const alertContext: SecurityAlertContext = {
      userId,
      alertType: SecurityAlertType.SUSPICIOUS_ACTIVITY,
      severity: 'high',
      metadata: {
        reason,
        ...metadata,
        timestamp: new Date(),
      },
    };

    await this.sendEmailAlert(user, alertContext);
  }

  private static async sendEmailAlert(
    user: User,
    context: SecurityAlertContext
  ) {
    // TODO: Implement email sending logic
    // This is where you'd integrate with your email service (SendGrid, AWS SES, etc.)

    const emailTemplate = this.getEmailTemplate(context);

    console.log(`
      [SECURITY ALERT]
      To: ${user.email}
      Subject: ${emailTemplate.subject}
      Body: ${emailTemplate.body}
    `);

    // Example with a hypothetical EmailService:
    // await EmailService.send({
    //   to: user.email,
    //   subject: emailTemplate.subject,
    //   html: emailTemplate.body,
    // });
  }

  private static getEmailTemplate(context: SecurityAlertContext) {
    const { alertType, metadata } = context;
    switch (alertType) {
      case SecurityAlertType.NEW_DEVICE:
        return {
          subject: 'New Device Detected on Your Account',
          body: `
            <h2>New Device Login Detected</h2>
            <p>We detected a login from a new device:</p>
            <ul>
              <li><strong>Device Type:</strong> ${metadata?.deviceType}</li>
              <li><strong>Location:</strong> ${metadata?.location || 'Unknown'}</li>
              <li><strong>IP Address:</strong> ${metadata?.ipAddress || 'Unknown'}</li>
              <li><strong>Time:</strong> ${metadata?.timestamp}</li>
            </ul>
            <p>If this was you, you can ignore this email. If not, please secure your account immediately.</p>
          `,
        };

      case SecurityAlertType.FAILED_LOGIN_ATTEMPTS:
        return {
          subject: 'Multiple Failed Login Attempts Detected',
          body: `
            <h2>Failed Login Attempts</h2>
            <p>We detected ${metadata?.attemptsCount} failed login attempts on your account.</p>
            <ul>
              <li><strong>Location:</strong> ${metadata?.location || 'Unknown'}</li>
              <li><strong>IP Address:</strong> ${metadata?.ipAddress || 'Unknown'}</li>
              <li><strong>Time:</strong> ${metadata?.timestamp}</li>
            </ul>
            <p>If this wasn't you, please secure your account immediately.</p>
          `,
        };

      case SecurityAlertType.ACCOUNT_LOCKED:
        return {
          subject: 'Your Account Has Been Locked',
          body: `
            <h2>Account Locked</h2>
            <p>Your account has been temporarily locked due to multiple failed login attempts.</p>
            <ul>
              <li><strong>Locked Until:</strong> ${metadata?.cooldownUntil}</li>
              <li><strong>Location:</strong> ${metadata?.location || 'Unknown'}</li>
              <li><strong>IP Address:</strong> ${metadata?.ipAddress || 'Unknown'}</li>
            </ul>
            <p>If you didn't attempt to log in, please contact support immediately.</p>
          `,
        };

      case SecurityAlertType.PASSWORD_CHANGED:
        return {
          subject: 'Your Password Was Changed',
          body: `
            <h2>Password Changed</h2>
            <p>Your password was recently changed.</p>
            <ul>
              <li><strong>Location:</strong> ${metadata?.location || 'Unknown'}</li>
              <li><strong>IP Address:</strong> ${metadata?.ipAddress || 'Unknown'}</li>
              <li><strong>Time:</strong> ${metadata?.timestamp}</li>
            </ul>
            <p>If you didn't make this change, please contact support immediately.</p>
          `,
        };

      case SecurityAlertType.SUSPICIOUS_ACTIVITY:
        return {
          subject: 'Suspicious Activity Detected',
          body: `
            <h2>Suspicious Activity Detected</h2>
            <p>We detected suspicious activity on your account.</p>
            <p><strong>Reason:</strong> ${metadata?.reason}</p>
            <p>Please review your recent account activity and secure your account if necessary.</p>
          `,
        };

      default:
        return {
          subject: 'Security Alert',
          body: '<p>We detected unusual activity on your account.</p>',
        };
    }
  }
}
