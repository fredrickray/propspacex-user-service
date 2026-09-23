import UserService from '@user/user.service';
import AuthService from '@auth/auth.service';
import Web3Service from '@web3/web3.service';
import DeviceService from '@security/device.service';
import ActivityService from '@security/activity.service';
import { Event } from '@security/activity.type';
import { TokenType } from '@auth/auth.type';
import ChatService from '@chat/chat.service';
import DealService from '@deal/deal.service';
import { withGrpcErrorHandler } from '../grpc-error.handler';
import {
  BadRequest,
  InvalidInput,
} from '@middlewares/error.middleware';
import { Conversation, Message } from '@chat/chat.entity';

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
      email: user.email,
      phone: '',
      appRole: user.appRole,
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
        appRole: result.user.appRole,
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

  createOrGetConversation = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { buyerId, agentId, propertyId } = call.request;

    if (!buyerId || !agentId) {
      throw new BadRequest('Buyer ID and agent ID are required');
    }

    const conversation = await ChatService.createOrGetConversation({
      buyerId,
      agentId,
      propertyId: propertyId || undefined,
    });

    callback(null, {
      success: true,
      conversation: this.toConversationResponse(conversation),
      error: '',
    });
  });

  sendChatMessage = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { conversationId, senderId, body } = call.request;

    if (!conversationId || !senderId || !body) {
      throw new BadRequest('Conversation ID, sender ID and message body are required');
    }

    const { message } = await ChatService.sendMessage({
      conversationId,
      senderId,
      body,
    });

    callback(null, {
      success: true,
      message: this.toMessageResponse(message),
      error: '',
    });
  });

  listConversations = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { userId, page, limit } = call.request;

    if (!userId) {
      throw new BadRequest('User ID is required');
    }

    const result = await ChatService.listConversations({
      userId,
      page: page || 1,
      limit: limit || 20,
    });

    callback(null, {
      conversations: result.data.map((entry) => ({
        conversation: this.toConversationResponse(entry.conversation),
        lastMessage: entry.lastMessage
          ? this.toMessageResponse(entry.lastMessage)
          : undefined,
        unreadCount: entry.unreadCount,
      })),
      total: result.total,
      page: result.page,
      limit: result.limit,
    });
  });

  listConversationMessages = withGrpcErrorHandler(
    async (call: any, callback: any) => {
      const { conversationId, userId, page, limit } = call.request;

      if (!conversationId || !userId) {
        throw new BadRequest('Conversation ID and user ID are required');
      }

      const result = await ChatService.listMessages({
        conversationId,
        userId,
        page: page || 1,
        limit: limit || 50,
      });

      callback(null, {
        messages: result.messages.map((message) => this.toMessageResponse(message)),
        total: result.total,
        page: result.page,
        limit: result.limit,
      });
    }
  );

  markConversationRead = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { conversationId, userId } = call.request;

    if (!conversationId || !userId) {
      throw new BadRequest('Conversation ID and user ID are required');
    }

    const updatedCount = await ChatService.markConversationAsRead({
      conversationId,
      userId,
    });

    callback(null, {
      success: true,
      updatedCount,
    });
  });

  createOrGetDeal = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { conversationId, userId, propertyTitle } = call.request;

    if (!conversationId || !userId) {
      throw new BadRequest('conversationId and userId are required');
    }

    const deal = await DealService.createOrGetByConversation({
      conversationId,
      userId,
      propertyTitle: propertyTitle || undefined,
    });

    callback(null, {
      success: true,
      deal: this.toDealResponse(deal),
      error: '',
    });
  });

  listDeals = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { userId, page, limit } = call.request;
    if (!userId) {
      throw new BadRequest('userId is required');
    }
    const result = await DealService.listDeals({
      userId,
      page: page || 1,
      limit: limit || 20,
    });
    callback(null, {
      deals: result.deals.map((deal) => this.toDealResponse(deal)),
      total: result.total,
      page: result.page,
      limit: result.limit,
    });
  });

  getDeal = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { dealId, userId } = call.request;
    if (!dealId || !userId) {
      throw new BadRequest('dealId and userId are required');
    }
    const deal = await DealService.getDealById({ dealId, userId });
    callback(null, { success: true, deal: this.toDealResponse(deal), error: '' });
  });

  quoteDeal = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { dealId, agentId, amountMinor, platformFeeMinor, quoteNote } = call.request;
    if (!dealId || !agentId) {
      throw new BadRequest('dealId and agentId are required');
    }
    const deal = await DealService.quoteDeal({
      dealId,
      agentId,
      amountMinor: Number(amountMinor),
      platformFeeMinor: Number(platformFeeMinor || 0),
      quoteNote: quoteNote || undefined,
    });
    callback(null, { success: true, deal: this.toDealResponse(deal), error: '' });
  });

  acceptDealQuote = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { dealId, buyerId, idempotencyKey } = call.request;
    if (!dealId || !buyerId || !idempotencyKey) {
      throw new BadRequest('dealId, buyerId and idempotencyKey are required');
    }
    const deal = await DealService.acceptQuote({
      dealId,
      buyerId,
      idempotencyKey,
    });
    callback(null, { success: true, deal: this.toDealResponse(deal), error: '' });
  });

  private toConversationResponse(conversation: Conversation) {
    return {
      conversationId: conversation.id,
      buyerId: conversation.buyerId,
      agentId: conversation.agentId,
      propertyId: conversation.propertyId || '',
      status: conversation.status,
      createdAt: conversation.createdAt?.toISOString() || '',
      updatedAt: conversation.updatedAt?.toISOString() || '',
      lastMessageAt: conversation.lastMessageAt?.toISOString() || '',
    };
  }

  private toMessageResponse(message: Message) {
    return {
      messageId: message.id,
      conversationId: message.conversationId,
      senderId: message.senderId,
      recipientId: message.recipientId,
      body: message.body,
      messageType: message.messageType,
      createdAt: message.createdAt?.toISOString() || '',
      readAt: message.readAt?.toISOString() || '',
    };
  }

  private toDealResponse(deal: any) {
    return {
      dealId: deal.dealId,
      conversationId: deal.conversationId,
      propertyId: deal.propertyId || '',
      propertyTitle: deal.propertyTitle || '',
      buyerId: deal.buyerId,
      buyerName: deal.buyerName || '',
      agentId: deal.agentId,
      agentName: deal.agentName || '',
      status: deal.status,
      quotedAmountMinor: deal.quotedAmountMinor || 0,
      platformFeeMinor: deal.platformFeeMinor || 0,
      quoteNote: deal.quoteNote || '',
      escrowId: deal.escrowId || '',
      createdAt: deal.createdAt || '',
      updatedAt: deal.updatedAt || '',
      quotedAt: deal.quotedAt || '',
      acceptedAt: deal.acceptedAt || '',
    };
  }


  // ==================== Web3 Authentication ====================

  /**
   * Generate a nonce for wallet authentication
   */
  requestWeb3Nonce = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { walletAddress, appRole } = call.request;

    if (!walletAddress) {
      throw new BadRequest('Wallet address is required');
    }

    const { nonce, message } = await Web3Service.requestNonce(walletAddress, appRole);

    callback(null, {
      success: true,
      nonce,
      message,
      error: '',
    });
  });

  /**
   * Verify wallet signature and authenticate
   */
  verifyWeb3Signature = withGrpcErrorHandler(
    async (call: any, callback: any) => {
      const { walletAddress, signature, message } = call.request;

      if (!walletAddress || !signature || !message) {
        throw new BadRequest(
          'Wallet address, signature, and message are required'
        );
      }

      const peer = call.getPeer() || '';
      const ipAddress = peer.split(':')[0] || 'unknown';

      const result = await Web3Service.verifySignature(
        walletAddress,
        signature,
        message,
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
          appRole: result.user.appRole,
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
    }
  );

  /**
   * Link a wallet to an existing user account
   */
  linkWeb3Wallet = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { userId, walletAddress } = call.request;

    if (!userId || !walletAddress) {
      throw new BadRequest('User ID and wallet address are required');
    }

    const wallet = await Web3Service.linkWallet(userId, walletAddress);

    callback(null, {
      success: true,
      walletAddress: wallet.walletAddress,
      isPrimary: wallet.isPrimary,
      error: '',
    });
  });

  /**
   * Unlink a wallet from an existing user account
   */
  unlinkWeb3Wallet = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { userId, walletAddress } = call.request;

    if (!userId || !walletAddress) {
      throw new BadRequest('User ID and wallet address are required');
    }

    await Web3Service.unlinkWallet(userId, walletAddress);

    callback(null, {
      success: true,
      message: 'Wallet unlinked successfully',
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

  /**
   * Refresh access token - called by API Gateway
   */
  refreshToken = withGrpcErrorHandler(async (call: any, callback: any) => {
    const { refreshToken } = call.request;

    if (!refreshToken) {
      throw new BadRequest('Refresh token is required');
    }

    // Verify the refresh token
    const decoded = await AuthService.verifyJWT(
      refreshToken,
      TokenType.REFRESH
    );
    const userId = decoded.sub as string;

    // Get user from database
    const user = await UserService.getUserById(userId);

    if (!user.isAccountActive) {
      throw new BadRequest('Account is deactivated');
    }

    // Generate new token pair
    const tokens = await AuthService.generateTokens(user);

    callback(null, {
      success: true,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      error: '',
    });
  });
}
