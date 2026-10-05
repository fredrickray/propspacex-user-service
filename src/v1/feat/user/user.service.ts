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
    const result = await this.listUsers(page, limit);
    return result.users;
  }

  static async listUsers(
    page = 1,
    limit = 10,
    search = ''
  ): Promise<{ users: User[]; total: number; page: number; limit: number }> {
    const safePage = Number.isFinite(page) && page > 0 ? Math.floor(page) : 1;
    const safeLimit =
      Number.isFinite(limit) && limit > 0
        ? Math.min(Math.floor(limit), 100)
        : 10;
    const term = search.trim();

    const query = this.userRepo.createQueryBuilder('user');
    if (term) {
      query.where(
        '(user.firstName ILIKE :term OR user.lastName ILIKE :term OR user.email ILIKE :term)',
        { term: `%${term}%` }
      );
    }

    const [users, total] = await query
      .orderBy('user.createdAt', 'DESC')
      .skip((safePage - 1) * safeLimit)
      .take(safeLimit)
      .getManyAndCount();

    return { users, total, page: safePage, limit: safeLimit };
  }

  static async listUnverifiedUsers(page = 1, limit = 20) {
    const safePage = Number.isFinite(page) && page > 0 ? Math.floor(page) : 1;
    const safeLimit =
      Number.isFinite(limit) && limit > 0
        ? Math.min(Math.floor(limit), 100)
        : 20;
    const [users, total] = await this.userRepo.findAndCount({
      where: { isVerified: false },
      order: { createdAt: 'DESC' },
      skip: (safePage - 1) * safeLimit,
      take: safeLimit,
    });
    return { users, total, page: safePage, limit: safeLimit };
  }

  static async updateProfile(input: {
    userId: string;
    firstName?: string;
    lastName?: string;
    email?: string;
  }): Promise<User> {
    const user = await this.getUserById(input.userId);
    const firstName = input.firstName?.trim() ?? '';
    const lastName = input.lastName?.trim() ?? '';
    const email = input.email?.trim() ?? '';

    if (!firstName || !lastName || !email) {
      throw new InvalidInput('First name, last name, and email are required');
    }

    if (email.toLowerCase() !== user.email.toLowerCase()) {
      const existing = await this.userRepo
        .createQueryBuilder('user')
        .where('LOWER(user.email) = LOWER(:email)', { email })
        .getOne();
      if (existing && existing.id !== user.id) {
        throw new BadRequest('Email is already in use');
      }
      user.email = email;
    }

    user.firstName = firstName;
    user.lastName = lastName;
    user.updatedAt = new Date();
    return this.userRepo.save(user);
  }

  static async deleteUser(userId: string): Promise<void> {
    const user = await this.getUserById(userId);
    await this.userRepo.remove(user);
  }
}
