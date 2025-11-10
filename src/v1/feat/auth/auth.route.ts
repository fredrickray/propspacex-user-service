import { Router } from 'express';
import AuthController from './auth.controller';

const authRouter = Router();

authRouter.post('/signup', AuthController.signup.bind(AuthController));

authRouter
  .route('/verifyEmail')
  .post(AuthController.verifyOTP.bind(AuthController));

authRouter
  .route('/resendOTP')
  .post(AuthController.resendOTP.bind(AuthController));

authRouter.post('/signin', AuthController.signin.bind(AuthController));

export default authRouter;
