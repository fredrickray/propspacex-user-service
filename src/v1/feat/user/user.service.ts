import {
  BadRequest,
  InvalidInput,
  ResourceNotFound,
  Unauthorized,
  TooManyRequests,
} from '@middlewares/error.middleware';
import { AppDataSource } from '@config/data.source';
import { User } from '@user/user.entity';

export default class UserService {
  private static userRepo = AppDataSource.getRepository(User);

  static async getUserById(userId: string): Promise<User> {
    if (!userId) throw new InvalidInput('User ID is required');

    const user = await this.userRepo.findOneBy({ id: userId });
    if (!user) throw new ResourceNotFound('User not found');

    return user;
  }

  static async getUserByEmail(email: string): Promise<User> {
    if (!email) throw new InvalidInput('Email is required');

    const user = await this.userRepo.findOneBy({ email });
    if (!user) throw new ResourceNotFound('User not found');

    return user;
  }

  static async getAllUsers(page = 1, limit = 10): Promise<User[]> {
    const skip = (page - 1) * limit;
    const users = await this.userRepo.find({
      skip,
      take: limit,
    });
    return users;
  }
}
