import { AppDataSource } from '@config/data.source';
import { ActivityLog } from './activity.entity';
import { Event } from './activity.type';

const activityRepo = AppDataSource.getRepository(ActivityLog);

export default class ActivityService {
  static async log(
    event: Event,
    data: {
      userId?: string | null;
      ip?: string | null;
      userAgent?: string | null;
      location?: string | null;
      deviceId?: string | null;
      metadata?: Record<string, any> | null;
    }
  ) {
    const activity = activityRepo.create({
      event,
      userId: data.userId ?? null,
      ip: data.ip ?? null,
      userAgent: data.userAgent ?? null,
      location: data.location ?? null,
      deviceId: data.deviceId ?? null,
      metadata: data.metadata ? JSON.stringify(data.metadata) : null,
    });
    await activityRepo.save(activity);
    return activity;
  }

  static async listRecent(userId: string, limit = 50) {
    return activityRepo.find({
      where: { userId },
      order: { timestamp: 'DESC' },
      take: limit,
    });
  }

  static async listAll(page = 1, limit = 20) {
    const safePage = page > 0 ? page : 1;
    const safeLimit = limit > 0 ? Math.min(limit, 100) : 20;
    const [logs, total] = await activityRepo.findAndCount({
      order: { timestamp: 'DESC' },
      skip: (safePage - 1) * safeLimit,
      take: safeLimit,
    });
    return { logs, total, page: safePage, limit: safeLimit };
  }
}
