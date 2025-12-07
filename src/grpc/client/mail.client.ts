/**
 * PropSpaceX Mail Service - gRPC Client
 *
 * This client can be copied to other microservices to communicate with the mail service.
 *
 * Usage:
 * ```typescript
 * import { MailServiceClient } from './grpc/clients/mail.client';
 *
 * const mailClient = new MailServiceClient('localhost:50051');
 *
 * // Send welcome email after signup
 * await mailClient.sendWelcomeEmail({
 *   recipientEmail: user.email,
 *   firstName: user.firstName,
 *   lastName: user.lastName,
 *   appRole: user.appRole,
 *   verificationLink: 'https://app.propspacex.com/verify?token=xxx'
 * });
 * ```
 */

import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import path from 'path';

// Proto loader options
const protoLoaderOptions: protoLoader.Options = {
  keepCase: false,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
};

// ==================== Type Definitions ====================

export interface SendEmailParams {
  recipientEmail: string;
  subject: string;
  bodyHtml?: string;
  templateName?: string;
  placeholders?: Record<string, string>;
}

export interface WelcomeEmailParams {
  recipientEmail: string;
  firstName: string;
}

export interface VerificationEmailParams {
  recipientEmail: string;
  verificationCode: string;
}

export interface PasswordResetEmailParams {
  recipientEmail: string;
  firstName: string;
  resetLink: string;
  resetCode?: string;
  expiryMinutes: number;
}

export interface PasswordChangedEmailParams {
  recipientEmail: string;
  firstName: string;
  changedAt: string;
  ipAddress: string;
  deviceInfo: string;
  location: string;
}

export interface LoginAlertEmailParams {
  recipientEmail: string;
  firstName: string;
  loginTime: string;
  ipAddress: string;
  deviceInfo: string;
  location: string;
  isNewDevice: boolean;
}

export interface InvitationEmailParams {
  recipientEmail: string;
  inviterName: string;
  organizationName: string;
  role: string;
  invitationLink: string;
  expiryDays: number;
}

export interface NotificationEmailParams {
  recipientEmail: string;
  firstName: string;
  subject: string;
  title: string;
  message: string;
  actionLink?: string;
  actionText?: string;
  notificationType: 'info' | 'warning' | 'success' | 'error';
}

export interface BulkEmailParams {
  recipientEmails: string[];
  subject: string;
  templateName: string;
  placeholders?: Record<string, string>;
}

export interface SendEmailResponse {
  success: boolean;
  messageId: string;
  statusMessage: string;
  queuedAt: string;
}

export interface BulkEmailResponse {
  success: boolean;
  totalQueued: number;
  totalFailed: number;
  failedEmails: string[];
  statusMessage: string;
}

export interface HealthResponse {
  status: 'UNKNOWN' | 'SERVING' | 'NOT_SERVING';
  version: string;
  uptime: string;
}

// ==================== Mail Service Client ====================

export class MailServiceClient {
  private client: any;
  private connected: boolean = false;

  /**
   * Create a new Mail Service client
   * @param address - gRPC server address (e.g., 'localhost:50051' or 'mail-service:50051')
   * @param protoPath - Optional custom path to mail.proto file
   */
  constructor(
    private address: string,
    protoPath?: string
  ) {
    const PROTO_PATH = protoPath || path.join(__dirname, '../proto/mail.proto');
    const packageDefinition = protoLoader.loadSync(
      PROTO_PATH,
      protoLoaderOptions
    );
    const mailProto = grpc.loadPackageDefinition(packageDefinition) as any;

    this.client = new mailProto.mail.MailerService(
      address,
      grpc.credentials.createInsecure()
    );
  }

  /**
   * Promisify gRPC call
   */
  private promisify<T>(
    method: string,
    params: Record<string, any>
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      // keepCase: false in proto-loader handles camelCase <-> snake_case conversion
      this.client[method](params, (error: any, response: T) => {
        if (error) {
          reject(error);
        } else {
          resolve(response);
        }
      });
    });
  }

  /**
   * Send a generic email
   */
  async sendEmail(params: SendEmailParams): Promise<SendEmailResponse> {
    return this.promisify<SendEmailResponse>('SendEmail', params);
  }

  /**
   * Send welcome email to new users
   */
  async sendWelcomeEmail(
    params: WelcomeEmailParams
  ): Promise<SendEmailResponse> {
    return this.promisify<SendEmailResponse>('SendWelcomeEmail', params);
  }

  /**
   * Send email verification email
   */
  async sendVerificationEmail(
    params: VerificationEmailParams
  ): Promise<SendEmailResponse> {
    return this.promisify<SendEmailResponse>('SendVerificationEmail', params);
  }

  /**
   * Send password reset email
   */
  async sendPasswordResetEmail(
    params: PasswordResetEmailParams
  ): Promise<SendEmailResponse> {
    return this.promisify<SendEmailResponse>('SendPasswordResetEmail', params);
  }

  /**
   * Send password changed notification
   */
  async sendPasswordChangedEmail(
    params: PasswordChangedEmailParams
  ): Promise<SendEmailResponse> {
    return this.promisify<SendEmailResponse>(
      'SendPasswordChangedEmail',
      params
    );
  }

  /**
   * Send login alert email
   */
  async sendLoginAlertEmail(
    params: LoginAlertEmailParams
  ): Promise<SendEmailResponse> {
    return this.promisify<SendEmailResponse>('SendLoginAlertEmail', params);
  }

  /**
   * Send invitation email
   */
  async sendInvitationEmail(
    params: InvitationEmailParams
  ): Promise<SendEmailResponse> {
    return this.promisify<SendEmailResponse>('SendInvitationEmail', params);
  }

  /**
   * Send notification email
   */
  async sendNotificationEmail(
    params: NotificationEmailParams
  ): Promise<SendEmailResponse> {
    return this.promisify<SendEmailResponse>('SendNotificationEmail', params);
  }

  /**
   * Send bulk emails
   */
  async sendBulkEmail(params: BulkEmailParams): Promise<BulkEmailResponse> {
    return this.promisify<BulkEmailResponse>('SendBulkEmail', params);
  }

  /**
   * Check service health
   */
  async checkHealth(
    serviceName: string = 'mail-service'
  ): Promise<HealthResponse> {
    return this.promisify<HealthResponse>('CheckHealth', { serviceName });
  }

  /**
   * Close the client connection
   */
  close(): void {
    if (this.client) {
      grpc.closeClient(this.client);
    }
  }

  /**
   * Wait for the client to be ready
   */
  async waitForReady(timeoutMs: number = 5000): Promise<void> {
    return new Promise((resolve, reject) => {
      const deadline = Date.now() + timeoutMs;
      this.client.waitForReady(deadline, (error: any) => {
        if (error) {
          reject(
            new Error(
              `Failed to connect to mail service at ${this.address}: ${error.message}`
            )
          );
        } else {
          this.connected = true;
          resolve();
        }
      });
    });
  }

  /**
   * Check if connected
   */
  isConnected(): boolean {
    return this.connected;
  }
}

// ==================== Singleton Factory ====================

let defaultClient: MailServiceClient | null = null;

/**
 * Get or create a singleton Mail Service client
 * @param address - gRPC server address (only used on first call)
 */
export const getMailClient = (address?: string): MailServiceClient => {
  if (!defaultClient) {
    const serverAddress =
      address || process.env.MAIL_SERVICE_GRPC_URL || 'localhost:50051';
    defaultClient = new MailServiceClient(serverAddress);
  }
  return defaultClient;
};

/**
 * Close the singleton client
 */
export const closeMailClient = (): void => {
  if (defaultClient) {
    defaultClient.close();
    defaultClient = null;
  }
};

export default MailServiceClient;
