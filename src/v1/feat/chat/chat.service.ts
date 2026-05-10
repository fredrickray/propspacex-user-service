import { AppDataSource } from '@config/data.source';
import {
  BadRequest,
  Forbidden,
  InvalidInput,
  ResourceNotFound,
} from '@middlewares/error.middleware';
import { AppRoles } from '@user/user.type';
import { User } from '@user/user.entity';
import { Conversation, Message } from './chat.entity';
import { ConversationStatus, MessageType } from './chat.type';
import {
  createConversationValidationSchema,
  listConversationMessagesValidationSchema,
  listConversationsValidationSchema,
  markConversationReadValidationSchema,
  sendMessageValidationSchema,
} from '@validations/chat.validations';

const userRepo = AppDataSource.getRepository(User);
const conversationRepo = AppDataSource.getRepository(Conversation);
const messageRepo = AppDataSource.getRepository(Message);

export default class ChatService {
  private static formatUserName(user: User | null | undefined): string | null {
    if (!user) return null;
    const fullName = `${user.firstName || ''} ${user.lastName || ''}`.trim();
    return fullName || null;
  }

  static async createOrGetConversation(params: {
    buyerId: string;
    agentId: string;
    propertyId?: string;
  }) {
    const { error } = createConversationValidationSchema.validate(params);
    if (error) {
      throw new InvalidInput(error.details.map((detail) => detail.message).join(', '));
    }

    if (params.buyerId === params.agentId) {
      throw new BadRequest('Buyer and agent must be different users');
    }

    const [buyer, agent] = await Promise.all([
      userRepo.findOneBy({ id: params.buyerId }),
      userRepo.findOneBy({ id: params.agentId }),
    ]);

    if (!buyer) {
      throw new ResourceNotFound('Buyer not found');
    }

    if (!agent) {
      throw new ResourceNotFound('Agent not found');
    }

    if (buyer.appRole !== AppRoles.BUYER) {
      throw new BadRequest('Conversation initiator must be a buyer');
    }

    if (agent.appRole !== AppRoles.AGENT) {
      throw new BadRequest('Receiver must be an agent');
    }

    const propertyId = params.propertyId ?? null;

    const query = conversationRepo
      .createQueryBuilder('conversation')
      .where('conversation.buyerId = :buyerId', { buyerId: params.buyerId })
      .andWhere('conversation.agentId = :agentId', { agentId: params.agentId });

    if (propertyId) {
      query.andWhere('conversation.propertyId = :propertyId', { propertyId });
    } else {
      query.andWhere('conversation.propertyId IS NULL');
    }

    const conversation = await query.getOne();

    if (conversation) {
      return conversation;
    }

    return conversationRepo.save(
      conversationRepo.create({
        buyerId: params.buyerId,
        agentId: params.agentId,
        propertyId,
        status: ConversationStatus.ACTIVE,
      })
    );
  }

  static async sendMessage(params: {
    conversationId: string;
    senderId: string;
    body: string;
    messageType?: MessageType;
    metadata?: Record<string, any> | null;
  }) {
    const { error } = sendMessageValidationSchema.validate(params);
    if (error) {
      throw new InvalidInput(error.details.map((detail) => detail.message).join(', '));
    }

    const conversation = await conversationRepo.findOneBy({ id: params.conversationId });
    if (!conversation) {
      throw new ResourceNotFound('Conversation not found');
    }

    if (
      params.senderId !== conversation.buyerId &&
      params.senderId !== conversation.agentId
    ) {
      throw new Forbidden('You are not a participant in this conversation');
    }

    if (conversation.status !== ConversationStatus.ACTIVE) {
      throw new BadRequest('Cannot send message to a closed or archived conversation');
    }

    const recipientId =
      params.senderId === conversation.buyerId
        ? conversation.agentId
        : conversation.buyerId;

    const message = await AppDataSource.transaction(async (manager) => {
      const createdMessage = await manager.save(
        Message,
        manager.create(Message, {
          conversationId: conversation.id,
          senderId: params.senderId,
          recipientId,
          body: params.body.trim(),
          messageType: params.messageType ?? MessageType.TEXT,
          metadata: params.metadata ?? null,
        })
      );

      await manager.update(
        Conversation,
        { id: conversation.id },
        {
          lastMessageAt: createdMessage.createdAt,
          updatedAt: () => 'CURRENT_TIMESTAMP' as any,
        }
      );

      return createdMessage;
    });

    const [sender, recipient] = await Promise.all([
      userRepo.findOneBy({ id: params.senderId }),
      userRepo.findOneBy({ id: recipientId }),
    ]);

    return {
      message,
      recipientId,
      senderName: this.formatUserName(sender),
      recipientName: this.formatUserName(recipient),
    };
  }

  static async listConversations(params: {
    userId: string;
    page?: number;
    limit?: number;
  }) {
    const { error } = listConversationsValidationSchema.validate(params);
    if (error) {
      throw new InvalidInput(error.details.map((detail) => detail.message).join(', '));
    }

    const page = params.page ?? 1;
    const limit = params.limit ?? 20;
    const offset = (page - 1) * limit;

    const qb = conversationRepo
      .createQueryBuilder('conversation')
      .leftJoinAndSelect('conversation.buyer', 'buyer')
      .leftJoinAndSelect('conversation.agent', 'agent')
      .where('conversation.buyerId = :userId OR conversation.agentId = :userId', {
        userId: params.userId,
      })
      .orderBy('conversation.lastMessageAt', 'DESC', 'NULLS LAST')
      .addOrderBy('conversation.createdAt', 'DESC')
      .skip(offset)
      .take(limit);

    const [conversations, total] = await qb.getManyAndCount();

    const conversationIds = conversations.map((conversation) => conversation.id);

    let lastMessages = new Map<string, Message>();
    let unreadCountMap = new Map<string, number>();

    if (conversationIds.length > 0) {
      const latestMessages = await messageRepo
        .createQueryBuilder('message')
        .distinctOn(['message.conversationId'])
        .where('message.conversationId IN (:...conversationIds)', { conversationIds })
        .orderBy('message.conversationId', 'ASC')
        .addOrderBy('message.createdAt', 'DESC')
        .getMany();

      lastMessages = new Map(
        latestMessages.map((message) => [message.conversationId, message])
      );

      const unreadCounts = await messageRepo
        .createQueryBuilder('message')
        .select('message.conversationId', 'conversationId')
        .addSelect('COUNT(message.id)', 'count')
        .where('message.conversationId IN (:...conversationIds)', { conversationIds })
        .andWhere('message.recipientId = :userId', { userId: params.userId })
        .andWhere('message.readAt IS NULL')
        .groupBy('message.conversationId')
        .getRawMany<{ conversationId: string; count: string }>();

      unreadCountMap = new Map(
        unreadCounts.map((row) => [row.conversationId, Number(row.count)])
      );
    }

    return {
      data: conversations.map((conversation) => ({
        conversation,
        lastMessage: lastMessages.get(conversation.id) ?? null,
        unreadCount: unreadCountMap.get(conversation.id) ?? 0,
      })),
      total,
      page,
      limit,
    };
  }

  static async listMessages(params: {
    conversationId: string;
    userId: string;
    page?: number;
    limit?: number;
  }) {
    const { error } = listConversationMessagesValidationSchema.validate(params);
    if (error) {
      throw new InvalidInput(error.details.map((detail) => detail.message).join(', '));
    }

    const conversation = await this.assertConversationParticipant(
      params.conversationId,
      params.userId
    );

    const page = params.page ?? 1;
    const limit = params.limit ?? 50;
    const offset = (page - 1) * limit;

    const [messages, total] = await messageRepo.findAndCount({
      where: { conversationId: conversation.id },
      order: { createdAt: 'DESC' },
      skip: offset,
      take: limit,
    });

    return { messages, total, page, limit, conversation };
  }

  static async markConversationAsRead(params: { conversationId: string; userId: string }) {
    const { error } = markConversationReadValidationSchema.validate(params);
    if (error) {
      throw new InvalidInput(error.details.map((detail) => detail.message).join(', '));
    }

    await this.assertConversationParticipant(params.conversationId, params.userId);

    const result = await messageRepo
      .createQueryBuilder()
      .update(Message)
      .set({ readAt: () => 'CURRENT_TIMESTAMP' as any })
      .where('conversationId = :conversationId', {
        conversationId: params.conversationId,
      })
      .andWhere('recipientId = :userId', { userId: params.userId })
      .andWhere('readAt IS NULL')
      .execute();

    return result.affected ?? 0;
  }

  static async getConversationForParticipant(conversationId: string, userId: string) {
    return this.assertConversationParticipant(conversationId, userId);
  }

  static async getConversationForParticipantWithParticipants(
    conversationId: string,
    userId: string
  ) {
    await this.assertConversationParticipant(conversationId, userId);
    const conversation = await conversationRepo.findOne({
      where: { id: conversationId },
      relations: ['buyer', 'agent'],
    });

    if (!conversation) {
      throw new ResourceNotFound('Conversation not found');
    }

    return {
      ...conversation,
      buyerName: this.formatUserName(conversation.buyer),
      agentName: this.formatUserName(conversation.agent),
    };
  }

  private static async assertConversationParticipant(
    conversationId: string,
    userId: string
  ) {
    const conversation = await conversationRepo.findOneBy({ id: conversationId });
    if (!conversation) {
      throw new ResourceNotFound('Conversation not found');
    }

    if (conversation.buyerId !== userId && conversation.agentId !== userId) {
      throw new Forbidden('You are not a participant in this conversation');
    }

    return conversation;
  }
}
