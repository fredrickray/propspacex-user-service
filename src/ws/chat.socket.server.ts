import { IncomingMessage, Server as HttpServer } from 'http';
import { URL } from 'url';
import { RawData, WebSocketServer, WebSocket } from 'ws';
import AuthService from '@auth/auth.service';
import { TokenType } from '@auth/auth.type';
import UserService from '@user/user.service';
import ChatService from '@chat/chat.service';
import { Conversation, Message } from '@chat/chat.entity';
import DealService from '@deal/deal.service';
import { HttpError } from '@middlewares/error.middleware';

type AuthenticatedSocket = WebSocket & { userId?: string };

type IncomingEvent = {
  event: string;
  requestId?: string;
  data?: Record<string, unknown>;
};

type OutgoingEvent = {
  event: string;
  requestId?: string;
  success: boolean;
  data?: Record<string, unknown>;
  error?: { code: string; message: string };
};

export default class ChatSocketServer {
  private wsServer: WebSocketServer;
  private clientsByUser = new Map<string, Set<AuthenticatedSocket>>();

  constructor(server: HttpServer) {
    this.wsServer = new WebSocketServer({
      server,
      path: '/v1/ws/chat',
      perMessageDeflate: false,
    });

    this.wsServer.on('connection', (socket, request) => {
      this.handleConnection(socket as AuthenticatedSocket, request).catch((error) => {
        console.error('WS connection setup failed:', error);
        socket.close(1011, 'Initialization failed');
      });
    });
  }

  close() {
    this.wsServer.close();
  }

  private async handleConnection(socket: AuthenticatedSocket, request: IncomingMessage) {
    const userId = await this.authenticate(request);
    socket.userId = userId;
    this.addClient(userId, socket);

    this.send(socket, {
      event: 'connection.ready',
      success: true,
      data: { userId },
    });

    socket.on('message', (raw: RawData) => {
      this.handleMessage(socket, raw).catch((error) => {
        console.error('WS message handling failed:', error);
        if (error instanceof HttpError) {
          this.send(socket, {
            event: 'request.error',
            success: false,
            error: {
              code: `HTTP_${error.status}`,
              message: error.message,
            },
          });
          return;
        }
        this.send(socket, {
          event: 'request.error',
          success: false,
          error: { code: 'INTERNAL_ERROR', message: 'Unexpected error' },
        });
      });
    });

    socket.on('close', () => {
      this.removeClient(userId, socket);
    });

    socket.on('error', (error) => {
      console.error('WS socket error:', error);
    });
  }

  private async authenticate(request: IncomingMessage): Promise<string> {
    const authHeader = request.headers.authorization;
    const tokenFromHeader =
      typeof authHeader === 'string' && authHeader.startsWith('Bearer ')
        ? authHeader.slice(7)
        : '';

    const requestUrl = new URL(request.url || '', 'http://localhost');
    const tokenFromQuery = requestUrl.searchParams.get('accessToken') || '';
    const token = tokenFromHeader || tokenFromQuery;

    if (!token) {
      throw new Error('Missing access token');
    }

    const decoded = await AuthService.verifyJWT(token, TokenType.ACCESS);
    const userId = decoded.sub as string;

    if (!userId) {
      throw new Error('Invalid token subject');
    }

    const user = await UserService.getUserById(userId);
    if (!user.isAccountActive) {
      throw new Error('Account is deactivated');
    }

    return userId;
  }

  private async handleMessage(socket: AuthenticatedSocket, raw: RawData) {
    const payload = this.parsePayload(raw);
    const requestId = payload.requestId;
    const userId = socket.userId;

    if (!userId) {
      this.sendError(socket, 'UNAUTHENTICATED', 'Socket is not authenticated', requestId);
      return;
    }

    switch (payload.event) {
      case 'ping':
        this.send(socket, { event: 'pong', requestId, success: true });
        return;

      case 'conversation.create_or_get': {
        const conversation = await ChatService.createOrGetConversation({
          buyerId: userId,
          agentId: String(payload.data?.agentId || ''),
          propertyId: payload.data?.propertyId
            ? String(payload.data.propertyId)
            : undefined,
        });
        const conversationWithParticipants =
          await ChatService.getConversationForParticipantWithParticipants(
            conversation.id,
            userId
          );

        this.send(socket, {
          event: 'conversation.created',
          requestId,
          success: true,
          data: {
            conversation: this.serializeConversation(conversationWithParticipants),
          },
        });
        return;
      }

      case 'conversations.list': {
        const result = await ChatService.listConversations({
          userId,
          page: Number(payload.data?.page || 1),
          limit: Number(payload.data?.limit || 20),
        });

        this.send(socket, {
          event: 'conversations.listed',
          requestId,
          success: true,
          data: {
            total: result.total,
            page: result.page,
            limit: result.limit,
            conversations: result.data.map((entry) => ({
              conversation: this.serializeConversation(entry.conversation),
              lastMessage: entry.lastMessage
                ? this.serializeMessage(entry.lastMessage, {
                    senderName:
                      entry.lastMessage.senderId === entry.conversation.buyerId
                        ? this.getConversationName(entry.conversation, 'buyer')
                        : this.getConversationName(entry.conversation, 'agent'),
                    recipientName:
                      entry.lastMessage.recipientId === entry.conversation.buyerId
                        ? this.getConversationName(entry.conversation, 'buyer')
                        : this.getConversationName(entry.conversation, 'agent'),
                  })
                : null,
              unreadCount: entry.unreadCount,
            })),
          },
        });
        return;
      }

      case 'messages.list': {
        const result = await ChatService.listMessages({
          conversationId: String(payload.data?.conversationId || ''),
          userId,
          page: Number(payload.data?.page || 1),
          limit: Number(payload.data?.limit || 50),
        });
        const conversationWithParticipants =
          await ChatService.getConversationForParticipantWithParticipants(
            String(payload.data?.conversationId || ''),
            userId
          );

        this.send(socket, {
          event: 'messages.listed',
          requestId,
          success: true,
          data: {
            total: result.total,
            page: result.page,
            limit: result.limit,
            messages: result.messages.map((message) =>
              this.serializeMessage(message, {
                senderName:
                  message.senderId === conversationWithParticipants.buyerId
                    ? conversationWithParticipants.buyerName
                    : conversationWithParticipants.agentName,
                recipientName:
                  message.recipientId === conversationWithParticipants.buyerId
                    ? conversationWithParticipants.buyerName
                    : conversationWithParticipants.agentName,
              })
            ),
          },
        });
        return;
      }

      case 'message.send': {
        const result = await ChatService.sendMessage({
          conversationId: String(payload.data?.conversationId || ''),
          senderId: userId,
          body: String(payload.data?.body || ''),
        });

        const messagePayload = this.serializeMessage(result.message, {
          senderName: result.senderName,
          recipientName: result.recipientName,
        });

        this.broadcastToUser(userId, {
          event: 'message.new',
          success: true,
          data: { message: messagePayload },
        });
        this.broadcastToUser(result.recipientId, {
          event: 'message.new',
          success: true,
          data: { message: messagePayload },
        });

        this.send(socket, {
          event: 'message.sent',
          requestId,
          success: true,
          data: { message: messagePayload },
        });
        return;
      }

      case 'conversation.read': {
        const conversationId = String(payload.data?.conversationId || '');
        const updatedCount = await ChatService.markConversationAsRead({
          conversationId,
          userId,
        });
        const conversation = await ChatService.getConversationForParticipant(
          conversationId,
          userId
        );
        const otherUserId =
          conversation.buyerId === userId
            ? conversation.agentId
            : conversation.buyerId;

        const readPayload = { conversationId, readerId: userId, updatedCount };
        this.broadcastToUser(userId, {
          event: 'conversation.read',
          success: true,
          data: readPayload,
        });
        this.broadcastToUser(otherUserId, {
          event: 'conversation.read',
          success: true,
          data: readPayload,
        });

        this.send(socket, {
          event: 'conversation.read_ack',
          requestId,
          success: true,
          data: readPayload,
        });
        return;
      }

      case 'deal.create_or_get': {
        const deal = await DealService.createOrGetByConversation({
          conversationId: String(payload.data?.conversationId || ''),
          userId,
          propertyTitle: payload.data?.propertyTitle
            ? String(payload.data.propertyTitle)
            : undefined,
        });
        this.send(socket, {
          event: 'deal.ready',
          requestId,
          success: true,
          data: { deal },
        });
        return;
      }

      case 'deal.quote': {
        const deal = await DealService.quoteDeal({
          dealId: String(payload.data?.dealId || ''),
          agentId: userId,
          amountMinor: Number(payload.data?.amountMinor || 0),
          platformFeeMinor: Number(payload.data?.platformFeeMinor || 0),
          quoteNote: payload.data?.quoteNote ? String(payload.data.quoteNote) : undefined,
        });

        this.send(socket, {
          event: 'deal.quoted',
          requestId,
          success: true,
          data: { deal },
        });
        this.broadcastDealStatusChanged(deal);
        return;
      }

      case 'deal.accept_quote': {
        const deal = await DealService.acceptQuote({
          dealId: String(payload.data?.dealId || ''),
          buyerId: userId,
          idempotencyKey: String(payload.data?.idempotencyKey || requestId || ''),
        });

        this.send(socket, {
          event: 'deal.quote_accepted',
          requestId,
          success: true,
          data: { deal },
        });
        this.broadcastDealStatusChanged(deal);
        return;
      }

      default:
        this.sendError(socket, 'UNKNOWN_EVENT', 'Unsupported chat event', requestId);
    }
  }

  private parsePayload(raw: RawData): IncomingEvent {
    try {
      const parsed = JSON.parse(raw.toString()) as IncomingEvent;
      if (!parsed?.event) {
        throw new Error('Event is required');
      }
      return parsed;
    } catch {
      throw new Error('Invalid websocket payload');
    }
  }

  private addClient(userId: string, socket: AuthenticatedSocket) {
    const sockets = this.clientsByUser.get(userId) || new Set<AuthenticatedSocket>();
    sockets.add(socket);
    this.clientsByUser.set(userId, sockets);
  }

  private removeClient(userId: string, socket: AuthenticatedSocket) {
    const sockets = this.clientsByUser.get(userId);
    if (!sockets) {
      return;
    }
    sockets.delete(socket);
    if (sockets.size === 0) {
      this.clientsByUser.delete(userId);
    }
  }

  private broadcastToUser(userId: string, payload: OutgoingEvent) {
    const sockets = this.clientsByUser.get(userId);
    if (!sockets) {
      return;
    }
    for (const socket of sockets) {
      this.send(socket, payload);
    }
  }

  private send(socket: AuthenticatedSocket, payload: OutgoingEvent) {
    if (socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify(payload));
    }
  }

  private sendError(
    socket: AuthenticatedSocket,
    code: string,
    message: string,
    requestId?: string
  ) {
    this.send(socket, {
      event: 'request.error',
      requestId,
      success: false,
      error: { code, message },
    });
  }

  private broadcastDealStatusChanged(deal: {
    buyerId: string;
    agentId: string;
    [key: string]: unknown;
  }) {
    const payload = {
      event: 'deal.status_changed',
      success: true,
      data: { deal },
    };
    this.broadcastToUser(deal.buyerId, payload);
    this.broadcastToUser(deal.agentId, payload);
  }

  private getConversationName(
    conversation: Conversation,
    participant: 'buyer' | 'agent'
  ): string | null {
    const user = participant === 'buyer' ? conversation.buyer : conversation.agent;
    if (!user) {
      return null;
    }
    const fullName = `${user.firstName || ''} ${user.lastName || ''}`.trim();
    return fullName || null;
  }

  private serializeConversation(conversation: Conversation) {
    return {
      conversationId: conversation.id,
      buyerId: conversation.buyerId,
      buyerName: this.getConversationName(conversation, 'buyer'),
      agentId: conversation.agentId,
      agentName: this.getConversationName(conversation, 'agent'),
      propertyId: conversation.propertyId || null,
      status: conversation.status,
      createdAt: conversation.createdAt?.toISOString() || null,
      updatedAt: conversation.updatedAt?.toISOString() || null,
      lastMessageAt: conversation.lastMessageAt?.toISOString() || null,
    };
  }

  private serializeMessage(
    message: Message,
    names?: { senderName?: string | null; recipientName?: string | null }
  ) {
    return {
      messageId: message.id,
      conversationId: message.conversationId,
      senderId: message.senderId,
      senderName: names?.senderName || null,
      recipientId: message.recipientId,
      recipientName: names?.recipientName || null,
      body: message.body,
      messageType: message.messageType,
      metadata: message.metadata || null,
      readAt: message.readAt?.toISOString() || null,
      createdAt: message.createdAt?.toISOString() || null,
    };
  }
}
