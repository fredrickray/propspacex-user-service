import { Router } from 'express';
import authRoputer from '@auth/auth.route';

const indexRouter = Router();

indexRouter.use('/auth', authRoputer);

export default indexRouter;
