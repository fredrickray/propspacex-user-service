import { MigrationInterface, QueryRunner } from 'typeorm';

export class InitialSchema1772000000000 implements MigrationInterface {
  name = 'InitialSchema1772000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      DO $$ BEGIN
        CREATE TYPE "public"."User_approle_enum" AS ENUM('admin', 'buyer', 'agent');
      EXCEPTION
        WHEN duplicate_object THEN null;
      END $$;
    `);
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "User" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "firstName" character varying NOT NULL,
        "lastName" character varying NOT NULL,
        "email" character varying NOT NULL,
        "password" character varying NOT NULL,
        "appRole" "public"."User_approle_enum" NOT NULL DEFAULT 'buyer',
        "isVerified" boolean NOT NULL DEFAULT false,
        "isAccountActive" boolean NOT NULL DEFAULT true,
        "lastLoginDate" TIMESTAMP,
        "loginAttempts" integer NOT NULL DEFAULT 0,
        "allowedLoginAttempts" integer NOT NULL DEFAULT 5,
        "loginCooldown" TIMESTAMP,
        "createdAt" TIMESTAMP,
        CONSTRAINT "PK_User" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_User_email" UNIQUE ("email")
      )
    `);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "Device" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "userId" character varying NOT NULL,
        "deviceId" character varying NOT NULL,
        "deviceType" character varying NOT NULL,
        "ipAddress" character varying NOT NULL,
        "userAgent" text NOT NULL,
        "location" character varying,
        "isTrusted" boolean NOT NULL DEFAULT false,
        "isRevoked" boolean NOT NULL DEFAULT false,
        "firstLogin" TIMESTAMP NOT NULL DEFAULT now(),
        "lastActive" TIMESTAMP,
        CONSTRAINT "PK_Device" PRIMARY KEY ("id")
      )
    `);
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "IDX_Device_userId" ON "Device" ("userId")`
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "IDX_Device_deviceId" ON "Device" ("deviceId")`
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "IDX_Device_userId_deviceId" ON "Device" ("userId", "deviceId")`
    );

    await queryRunner.query(`
      DO $$ BEGIN
        CREATE TYPE "public"."ActivityLog_event_enum" AS ENUM(
          'USER_REGISTERED',
          'LOGIN_SUCCESS',
          'LOGIN_FAILED',
          'LOGOUT',
          'EMAIL_VERIFIED',
          'EMAIL_VERIFICATION_FAILED',
          'OTP_RESENT',
          'PASSWORD_RESET_REQUESTED',
          'PASSWORD_RESET_SUCCESS',
          'PASSWORD_CHANGED',
          'ACCOUNT_LOCKED',
          'ACCOUNT_UNLOCKED',
          'SUSPICIOUS_ACTIVITY',
          'DEVICE_TRUSTED',
          'DEVICE_REVOKED',
          'TOKEN_REFRESHED',
          'TOKEN_REVOKED',
          'PROFILE_UPDATED',
          'PROFILE_VIEWED',
          'ACCOUNT_DEACTIVATED',
          'ACCOUNT_REACTIVATED',
          'ACCOUNT_DELETED',
          'SECURITY_ALERT_SENT',
          'FAILED_LOGIN_ALERT',
          'ACCOUNT_LOCKED_ALERT'
        );
      EXCEPTION
        WHEN duplicate_object THEN null;
      END $$;
    `);
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "ActivityLog" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "userId" character varying,
        "event" "public"."ActivityLog_event_enum" NOT NULL,
        "ip" character varying,
        "userAgent" text,
        "location" character varying,
        "deviceId" character varying,
        "metadata" text,
        "timestamp" TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_ActivityLog" PRIMARY KEY ("id")
      )
    `);
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "IDX_ActivityLog_userId" ON "ActivityLog" ("userId")`
    );

    await queryRunner.query(`
      DO $$ BEGIN
        CREATE TYPE "public"."Token_tokentype_enum" AS ENUM(
          'access',
          'refresh',
          'Email Verification',
          'Reset Password'
        );
      EXCEPTION
        WHEN duplicate_object THEN null;
      END $$;
    `);
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "Token" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "userId" character varying NOT NULL,
        "token" character varying NOT NULL,
        "tokenType" "public"."Token_tokentype_enum" NOT NULL,
        "createdAt" TIMESTAMP NOT NULL DEFAULT now(),
        "expiresAt" TIMESTAMP,
        CONSTRAINT "PK_Token" PRIMARY KEY ("id")
      )
    `);
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "IDX_Token_userId" ON "Token" ("userId")`
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "IDX_Token_tokenType" ON "Token" ("tokenType")`
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "IDX_Token_userId_tokenType" ON "Token" ("userId", "tokenType")`
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "LoginAttempt" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "email" character varying NOT NULL,
        "success" boolean NOT NULL,
        "timestamp" TIMESTAMP NOT NULL DEFAULT now(),
        "ipAddress" character varying,
        CONSTRAINT "PK_LoginAttempt" PRIMARY KEY ("id")
      )
    `);
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "IDX_LoginAttempt_email" ON "LoginAttempt" ("email")`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS "LoginAttempt"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "Token"`);
    await queryRunner.query(`DROP TYPE IF EXISTS "public"."Token_tokentype_enum"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "ActivityLog"`);
    await queryRunner.query(
      `DROP TYPE IF EXISTS "public"."ActivityLog_event_enum"`
    );
    await queryRunner.query(`DROP TABLE IF EXISTS "Device"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "User"`);
    await queryRunner.query(`DROP TYPE IF EXISTS "public"."User_approle_enum"`);
  }
}
