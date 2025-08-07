import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

const DotenvConfig = {
  serverPort: process.env.PORT as unknown as number,
  Database: {
    type: process.env.DB_TYPE as string,
    host: process.env.DB_HOST as string,
    port: parseInt(process.env.DB_PORT as string),
    username: process.env.DB_USERNAME as string,
    password: process.env.DB_PASSWORD as string,
    database: process.env.DB_NAME as string,
    synchronize: process.env.DB_SYNCHRONIZE === 'false',
    logging: process.env.DB_LOGGING === 'true',
    entities: process.env.DB_ENTITIES ? process.env.DB_ENTITIES.split(',') : [],
    migrations: process.env.DB_MIGRATIONS
      ? process.env.DB_MIGRATIONS.split(',')
      : [],
    subscribers: process.env.DB_SUBSCRIBERS
      ? process.env.DB_SUBSCRIBERS.split(',')
      : [],
    cli: {
      entitiesDir: process.env.DB_ENTITIES_DIR as string,
      migrationsDir: process.env.DB_MIGRATIONS_DIR as string,
      subscribersDir: process.env.DB_SUBSCRIBERS_DIR as string,
    },
  },
  JWTHeader: {
    issuer: process.env.JWT_ISSUER as string,
    audience: process.env.JWT_AUDIENCE as string,
    algorithm: process.env.JWT_ALGORITHM as unknown as jwt.Algorithm,
    accessTokenSecret: process.env.ACCESS_TOKEN_SECRET as string,
    refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET as string,
  },
  TokenExpiry: {
    accessToken: parseInt(process.env.ACCESS_TOKEN_EXPIRY as string),
    refreshToken: parseInt(process.env.REFRESH_TOKEN_EXPIRY as string),
    rememberMe: parseInt(process.env.REMEMBER_ME_EXPIRY as string),
  },
  Cors: {
    origin: process.env.CORS_ORIGIN as string,
    methods: process.env.CORS_METHODS as string,
    allowedHeaders: process.env.CORS_ALLOWED_HEADERS as string,
    credentials: process.env.CORS_CREDENTIALS === 'true',
  },
  serverBaseURL: process.env.SERVER_BASE_URL as string,
  frontendBaseURL: process.env.FRONTEND_BASE_URL as string,
  BcryptSalt: parseInt(process.env.BCRYPT_SALT as string),
  CompanyName: process.env.COMPANY_NAME as string,
};

export default DotenvConfig;
