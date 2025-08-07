import DotenvConfig from './dotenv.config';
import { DataSource } from 'typeorm';
import { User } from '@user/user.entity';

export const AppDataSource = new DataSource({
  type: DotenvConfig.Database.type as any,
  host: DotenvConfig.Database.host,
  port: DotenvConfig.Database.port,
  username: DotenvConfig.Database.username,
  password: DotenvConfig.Database.password,
  database: DotenvConfig.Database.database,
  synchronize: DotenvConfig.Database.synchronize,
  logging: DotenvConfig.Database.logging,
  entities: [User],
  migrations: DotenvConfig.Database.migrations,
  subscribers: DotenvConfig.Database.subscribers,
});
