import { Router } from 'express';
import authRouter from '@auth/auth.route';
import web3Router from '@web3/web3.route';

const indexRouter = Router();

indexRouter.use('/auth', authRouter);
indexRouter.use('/web3', web3Router);

export default indexRouter;
