import { LoginAttempt, Token } from '@auth/auth.entity';
import * as migrations from '../migrations';
import { ActivityLog } from '@security/activity.entity';
import { Device } from '@security/device.entity';
import { User } from '@user/user.entity';
import { DataSource } from 'typeorm';
import DotenvConfig from './dotenv.config';

export const AppDataSource = new DataSource({
  type: DotenvConfig.Database.type as any,
  host: DotenvConfig.Database.host,
  port: DotenvConfig.Database.port,
  username: DotenvConfig.Database.username,
  password: DotenvConfig.Database.password,
  database: DotenvConfig.Database.database,
  synchronize: DotenvConfig.Database.synchronize,
  logging: DotenvConfig.Database.logging,
  entities: [User, Device, ActivityLog, Token, LoginAttempt],
  migrations: Object.values(migrations),
  subscribers: DotenvConfig.Database.subscribers,
  extra: {
    max: 20, // maximum number of connections in the pool
    min: 5, // minimum number of connections in the pool
    idleTimeoutMillis: 30000, // close idle clients after 30 seconds
    connectionTimeoutMillis: 2000, // return an error after 2 seconds if connection could not be established
  },
  cache: {
    duration: 30000, // cache duration in milliseconds
  },
});
