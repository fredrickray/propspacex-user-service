import { Router } from 'express';
import authRouter from '@auth/auth.route';
import web3Router from '@web3/web3.route';
import dealRouter from '@deal/deal.route';

const indexRouter = Router();

indexRouter.use('/auth', authRouter);
indexRouter.use('/web3', web3Router);
indexRouter.use('/deals', dealRouter);

export default indexRouter;
