import { Router } from 'express';
import authRouter from '@auth/auth.route';

const indexRouter = Router();

indexRouter.use('/auth', authRouter);

export default indexRouter;
