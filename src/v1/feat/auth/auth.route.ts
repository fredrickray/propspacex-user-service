import { Router } from 'express';
import AuthController from './auth.controller';

const authRoputer = Router();

authRoputer.post('/signup', AuthController.signup.bind(AuthController));

authRoputer.post('/signin', AuthController.signin.bind(AuthController));

export default authRoputer;
