import { Router } from 'express';
import DealController from './deal.controller';
import { authorizeUser } from '@middlewares/auth.middleware';

const dealRouter = Router();

dealRouter.use(authorizeUser);
dealRouter.post('/', DealController.createOrGetDeal.bind(DealController));
dealRouter.get('/', DealController.listDeals.bind(DealController));
dealRouter.get('/:dealId', DealController.getDeal.bind(DealController));
dealRouter.post('/:dealId/quote', DealController.quoteDeal.bind(DealController));
dealRouter.post('/:dealId/accept-quote', DealController.acceptQuote.bind(DealController));

export default dealRouter;
