export enum DealStatus {
  OPEN = 'open',
  QUOTED = 'quoted',
  FUNDING_READY = 'funding_ready',
  IN_PROGRESS = 'in_progress',
  PENDING_BUYER_RELEASE = 'pending_buyer_release',
  RELEASED = 'released',
  CANCELLED = 'cancelled',
  DISPUTED = 'disputed',
  REFUNDED = 'refunded',
}

export type DealSummary = {
  dealId: string;
  conversationId: string;
  propertyId: string | null;
  propertyTitle: string | null;
  buyerId: string;
  buyerName: string | null;
  agentId: string;
  agentName: string | null;
  status: DealStatus;
  quotedAmountMinor: number | null;
  platformFeeMinor: number | null;
  quoteNote: string | null;
  escrowId: string | null;
  createdAt: string | null;
  updatedAt: string | null;
  quotedAt: string | null;
  acceptedAt: string | null;
};
