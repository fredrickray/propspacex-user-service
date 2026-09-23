import { AppDataSource } from '@config/data.source';
import {
  BadRequest,
  Forbidden,
  ResourceNotFound,
} from '@middlewares/error.middleware';
import { Deal } from './deal.entity';
import { DealStatus, DealSummary } from './deal.type';
import { Conversation } from '@chat/chat.entity';
import PaymentServiceClient from '@grpc/client/payment.client';

const dealRepo = AppDataSource.getRepository(Deal);
const conversationRepo = AppDataSource.getRepository(Conversation);
const paymentClient = new PaymentServiceClient(process.env.PAYMENT_SERVICE_GRPC_URL as string);

const ESCROW_STATUS_TO_DEAL_STATUS: Record<string, DealStatus> = {
  ESCROW_STATUS_HELD: DealStatus.FUNDING_READY,
  ESCROW_STATUS_IN_PROGRESS: DealStatus.IN_PROGRESS,
  ESCROW_STATUS_PENDING_BUYER_RELEASE: DealStatus.PENDING_BUYER_RELEASE,
  ESCROW_STATUS_RELEASED: DealStatus.RELEASED,
  ESCROW_STATUS_CANCELLED: DealStatus.CANCELLED,
  ESCROW_STATUS_DISPUTED: DealStatus.DISPUTED,
  ESCROW_STATUS_REFUNDED: DealStatus.REFUNDED,
};

export default class DealService {
  private static fullName(firstName?: string | null, lastName?: string | null): string | null {
    const full = `${firstName || ''} ${lastName || ''}`.trim();
    return full || null;
  }

  private static toSummary(deal: Deal): DealSummary {
    return {
      dealId: deal.id,
      conversationId: deal.conversationId,
      propertyId: deal.propertyId || null,
      propertyTitle: deal.propertyTitle || null,
      buyerId: deal.buyerId,
      buyerName: this.fullName(deal.buyer?.firstName, deal.buyer?.lastName),
      agentId: deal.agentId,
      agentName: this.fullName(deal.agent?.firstName, deal.agent?.lastName),
      status: deal.status,
      quotedAmountMinor:
        typeof deal.quotedAmountMinor === 'number'
          ? deal.quotedAmountMinor
          : deal.quotedAmountMinor
          ? Number(deal.quotedAmountMinor)
          : null,
      platformFeeMinor:
        typeof deal.platformFeeMinor === 'number'
          ? deal.platformFeeMinor
          : deal.platformFeeMinor
          ? Number(deal.platformFeeMinor)
          : null,
      quoteNote: deal.quoteNote || null,
      escrowId: deal.escrowId || null,
      createdAt: deal.createdAt?.toISOString() || null,
      updatedAt: deal.updatedAt?.toISOString() || null,
      quotedAt: deal.quotedAt?.toISOString() || null,
      acceptedAt: deal.acceptedAt?.toISOString() || null,
    };
  }

  private static async applyEscrowStatus(deal: Deal): Promise<void> {
    if (!deal.escrowId) return;

    try {
      const escrowResponse = await paymentClient.getEscrowById(deal.escrowId);
      const escrowStatus = escrowResponse?.escrow?.status as string | undefined;
      if (!escrowStatus) return;
      const mapped = ESCROW_STATUS_TO_DEAL_STATUS[escrowStatus];
      if (mapped && mapped !== deal.status) {
        deal.status = mapped;
        await dealRepo.save(deal);
      }
    } catch {
      // Escrow reflection is best-effort to avoid blocking deal reads.
    }
  }

  static async createOrGetByConversation(params: {
    conversationId: string;
    userId: string;
    propertyTitle?: string;
  }) {
    const { conversationId, userId, propertyTitle } = params;
    const conversation = await conversationRepo.findOne({
      where: { id: conversationId },
      relations: ['buyer', 'agent'],
    });
    if (!conversation) {
      throw new ResourceNotFound('Conversation not found');
    }
    if (conversation.buyerId !== userId && conversation.agentId !== userId) {
      throw new Forbidden('You are not a participant in this conversation');
    }

    const existing = await dealRepo.findOne({
      where: { conversationId },
      relations: ['buyer', 'agent'],
    });
    if (existing) {
      await this.applyEscrowStatus(existing);
      return this.toSummary(existing);
    }

    const created = await dealRepo.save(
      dealRepo.create({
        conversationId: conversation.id,
        propertyId: conversation.propertyId || null,
        propertyTitle: propertyTitle || null,
        buyerId: conversation.buyerId,
        agentId: conversation.agentId,
        status: DealStatus.OPEN,
      })
    );
    const hydrated = await dealRepo.findOne({
      where: { id: created.id },
      relations: ['buyer', 'agent'],
    });
    if (!hydrated) {
      throw new ResourceNotFound('Deal not found after creation');
    }
    return this.toSummary(hydrated);
  }

  static async listDeals(params: {
    userId: string;
    page?: number;
    limit?: number;
  }) {
    const page = params.page || 1;
    const limit = params.limit || 20;
    const [deals, total] = await dealRepo.findAndCount({
      where: [{ buyerId: params.userId }, { agentId: params.userId }],
      relations: ['buyer', 'agent'],
      order: { updatedAt: 'DESC' },
      skip: (page - 1) * limit,
      take: limit,
    });
    for (const deal of deals) {
      await this.applyEscrowStatus(deal);
    }
    return {
      total,
      page,
      limit,
      deals: deals.map((deal) => this.toSummary(deal)),
    };
  }

  static async getDealById(params: { dealId: string; userId: string }) {
    const deal = await dealRepo.findOne({
      where: { id: params.dealId },
      relations: ['buyer', 'agent'],
    });
    if (!deal) {
      throw new ResourceNotFound('Deal not found');
    }
    if (deal.buyerId !== params.userId && deal.agentId !== params.userId) {
      throw new Forbidden('You are not a participant in this deal');
    }
    await this.applyEscrowStatus(deal);
    return this.toSummary(deal);
  }

  static async quoteDeal(params: {
    dealId: string;
    agentId: string;
    amountMinor: number;
    platformFeeMinor: number;
    quoteNote?: string;
  }) {
    const deal = await dealRepo.findOne({
      where: { id: params.dealId },
      relations: ['buyer', 'agent'],
    });
    if (!deal) {
      throw new ResourceNotFound('Deal not found');
    }
    if (deal.agentId !== params.agentId) {
      throw new Forbidden('Only the assigned agent can quote this deal');
    }
    if (params.amountMinor <= 0) {
      throw new BadRequest('amountMinor must be a positive integer');
    }
    if (params.platformFeeMinor < 0 || params.platformFeeMinor > params.amountMinor) {
      throw new BadRequest('platformFeeMinor must be between 0 and amountMinor');
    }

    deal.quotedAmountMinor = params.amountMinor;
    deal.platformFeeMinor = params.platformFeeMinor;
    deal.quoteNote = params.quoteNote || null;
    deal.quotedAt = new Date();
    deal.status = DealStatus.QUOTED;
    deal.updatedAt = new Date();
    const saved = await dealRepo.save(deal);
    return this.toSummary(saved);
  }

  static async acceptQuote(params: {
    dealId: string;
    buyerId: string;
    idempotencyKey: string;
  }) {
    const deal = await dealRepo.findOne({
      where: { id: params.dealId },
      relations: ['buyer', 'agent'],
    });
    if (!deal) {
      throw new ResourceNotFound('Deal not found');
    }
    if (deal.buyerId !== params.buyerId) {
      throw new Forbidden('Only the buyer can accept this quote');
    }
    if (deal.status !== DealStatus.QUOTED) {
      throw new BadRequest('Deal is not in quoted state');
    }
    if (!deal.quotedAmountMinor || deal.quotedAmountMinor <= 0) {
      throw new BadRequest('Cannot accept quote without quoted amount');
    }

    if (deal.escrowId) {
      await this.applyEscrowStatus(deal);
      return this.toSummary(deal);
    }

    const metadataJson = JSON.stringify({
      conversationId: deal.conversationId,
      propertyTitle: deal.propertyTitle || null,
    });

    const escrowResponse = await paymentClient.createEscrow({
      deal_ref: deal.id,
      buyer_user_id: deal.buyerId,
      agent_user_id: deal.agentId,
      property_id: deal.propertyId || '',
      currency_code: 1,
      amount_minor: Number(deal.quotedAmountMinor),
      platform_fee_minor: Number(deal.platformFeeMinor || 0),
      hold_funds_now: false,
      metadata_json: metadataJson,
      idempotency_key: params.idempotencyKey,
    });

    const escrowId = escrowResponse?.escrow?.escrowId;
    if (!escrowId) {
      throw new BadRequest('Escrow creation failed: missing escrow id');
    }

    deal.escrowId = escrowId;
    deal.status = DealStatus.FUNDING_READY;
    deal.acceptedAt = new Date();
    deal.updatedAt = new Date();

    const saved = await dealRepo.save(deal);
    return this.toSummary(saved);
  }
}
