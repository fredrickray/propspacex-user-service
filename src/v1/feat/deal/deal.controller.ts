import { NextFunction, Request, Response } from 'express';
import DealService from './deal.service';

export default class DealController {
  static async createOrGetDeal(req: Request, res: Response, next: NextFunction) {
    try {
      const userId = req.authUser?.id;
      if (!userId) {
        return res.status(401).json({ success: false, message: 'Authentication required' });
      }

      const { conversationId, propertyTitle } = req.body;
      const deal = await DealService.createOrGetByConversation({
        conversationId,
        userId,
        propertyTitle,
      });
      return res.status(200).json({ success: true, deal });
    } catch (error) {
      next(error);
    }
  }

  static async listDeals(req: Request, res: Response, next: NextFunction) {
    try {
      const userId = req.authUser?.id;
      if (!userId) {
        return res.status(401).json({ success: false, message: 'Authentication required' });
      }

      const page = Number(req.query.page || 1);
      const limit = Number(req.query.limit || 20);
      const result = await DealService.listDeals({ userId, page, limit });
      return res.status(200).json({ success: true, ...result });
    } catch (error) {
      next(error);
    }
  }

  static async getDeal(req: Request, res: Response, next: NextFunction) {
    try {
      const userId = req.authUser?.id;
      if (!userId) {
        return res.status(401).json({ success: false, message: 'Authentication required' });
      }
      const deal = await DealService.getDealById({
        dealId: req.params.dealId,
        userId,
      });
      return res.status(200).json({ success: true, deal });
    } catch (error) {
      next(error);
    }
  }

  static async quoteDeal(req: Request, res: Response, next: NextFunction) {
    try {
      const agentId = req.authUser?.id;
      if (!agentId) {
        return res.status(401).json({ success: false, message: 'Authentication required' });
      }

      const { amountMinor, platformFeeMinor, quoteNote } = req.body;
      const deal = await DealService.quoteDeal({
        dealId: req.params.dealId,
        agentId,
        amountMinor: Number(amountMinor),
        platformFeeMinor: Number(platformFeeMinor || 0),
        quoteNote,
      });
      return res.status(200).json({ success: true, deal });
    } catch (error) {
      next(error);
    }
  }

  static async acceptQuote(req: Request, res: Response, next: NextFunction) {
    try {
      const buyerId = req.authUser?.id;
      if (!buyerId) {
        return res.status(401).json({ success: false, message: 'Authentication required' });
      }

      const { idempotencyKey } = req.body;
      const deal = await DealService.acceptQuote({
        dealId: req.params.dealId,
        buyerId,
        idempotencyKey: String(idempotencyKey || ''),
      });
      return res.status(200).json({ success: true, deal });
    } catch (error) {
      next(error);
    }
  }
}
