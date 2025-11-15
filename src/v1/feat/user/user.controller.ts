import { Request, Response, NextFunction } from 'express';
import { Unauthorized } from '@middlewares/error.middleware';
import UserService from './user.service';

export default class UserController {
  static async getUser(req: Request, res: Response, next: NextFunction) {
    try {
      const userId = req.params.id;

      const user = await UserService.getUserById(userId);

      res.status(200).json({
        success: true,
        data: user,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getAllUsers(req: Request, res: Response, next: NextFunction) {
    try {
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 10;

      const users = await UserService.getAllUsers(page, limit);

      res.status(200).json({
        success: true,
        data: users,
      });
    } catch (error) {
      next(error);
    }
  }
}
