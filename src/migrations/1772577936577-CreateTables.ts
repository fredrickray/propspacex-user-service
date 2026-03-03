import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateTables1772577936577 implements MigrationInterface {
  name = 'CreateTables1772577936577';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TYPE "public"."User_approle_enum" AS ENUM('admin', 'buyer', 'agent')`
    );
    await queryRunner.query(
      `CREATE TABLE "User" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "firstName" character varying NOT NULL, "lastName" character varying NOT NULL, "email" character varying NOT NULL, "password" character varying NOT NULL, "profileImage" jsonb, "appRole" "public"."User_approle_enum" NOT NULL DEFAULT 'buyer', "isVerified" boolean NOT NULL DEFAULT false, "reAuth" boolean NOT NULL DEFAULT false, "tokenVersion" integer NOT NULL DEFAULT '0', "isAccountActive" boolean NOT NULL DEFAULT true, "lastLoginDate" TIMESTAMP, "loginAttempts" integer NOT NULL DEFAULT '0', "allowedLoginAttempts" integer NOT NULL DEFAULT '5', "loginCooldown" TIMESTAMP, "createdAt" TIMESTAMP, "updatedAt" TIMESTAMP, CONSTRAINT "UQ_4a257d2c9837248d70640b3e36e" UNIQUE ("email"), CONSTRAINT "PK_9862f679340fb2388436a5ab3e4" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_9862f679340fb2388436a5ab3e" ON "User" ("id") `
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_4a257d2c9837248d70640b3e36" ON "User" ("email") `
    );
    await queryRunner.query(
      `CREATE TABLE "Device" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "userId" character varying NOT NULL, "deviceId" character varying NOT NULL, "deviceType" character varying NOT NULL, "ipAddress" character varying NOT NULL, "userAgent" text NOT NULL, "location" character varying, "isTrusted" boolean NOT NULL DEFAULT false, "isRevoked" boolean NOT NULL DEFAULT false, "firstLogin" TIMESTAMP NOT NULL DEFAULT now(), "lastActive" TIMESTAMP, CONSTRAINT "PK_f0a3247774bd4eaad2177055336" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_f0a3247774bd4eaad217705533" ON "Device" ("id") `
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_dc1618bce8f5b8a05b1de99bf2" ON "Device" ("userId") `
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_f54a403562686cddb1a025fea8" ON "Device" ("deviceId") `
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_2db8a9718a1161eb428827faba" ON "Device" ("userId", "deviceId") `
    );
    await queryRunner.query(
      `CREATE TYPE "public"."ActivityLog_event_enum" AS ENUM('USER_REGISTERED', 'LOGIN_SUCCESS', 'LOGIN_FAILED', 'LOGOUT', 'EMAIL_VERIFIED', 'EMAIL_VERIFICATION_FAILED', 'OTP_RESENT', 'PASSWORD_RESET_REQUESTED', 'PASSWORD_RESET_SUCCESS', 'PASSWORD_CHANGED', 'ACCOUNT_LOCKED', 'ACCOUNT_UNLOCKED', 'SUSPICIOUS_ACTIVITY', 'DEVICE_TRUSTED', 'DEVICE_REVOKED', 'TOKEN_REFRESHED', 'TOKEN_REVOKED', 'PROFILE_UPDATED', 'PROFILE_VIEWED', 'ACCOUNT_DEACTIVATED', 'ACCOUNT_REACTIVATED', 'ACCOUNT_DELETED', 'SECURITY_ALERT_SENT', 'FAILED_LOGIN_ALERT', 'ACCOUNT_LOCKED_ALERT')`
    );
    await queryRunner.query(
      `CREATE TABLE "ActivityLog" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "userId" character varying, "event" "public"."ActivityLog_event_enum" NOT NULL, "ip" character varying, "userAgent" text, "location" character varying, "deviceId" character varying, "metadata" text, "timestamp" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "PK_399093f65413d2893d656e75e6b" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_9d3bf2db7fa484cefa22cfcd53" ON "ActivityLog" ("userId") `
    );
    await queryRunner.query(
      `CREATE TYPE "public"."Token_tokentype_enum" AS ENUM('access', 'refresh', 'Email Verification', 'Reset Password')`
    );
    await queryRunner.query(
      `CREATE TABLE "Token" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "userId" character varying NOT NULL, "token" character varying NOT NULL, "tokenType" "public"."Token_tokentype_enum" NOT NULL, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "expiresAt" TIMESTAMP, CONSTRAINT "PK_206d2a22c0a6839d849fb7016b5" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_662d4382153fd190df048bf0f6" ON "Token" ("userId") `
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_d8a2b91d7d64904668d2f1b517" ON "Token" ("tokenType") `
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_13f3208a3c2802d86170be9235" ON "Token" ("userId", "tokenType") `
    );
    await queryRunner.query(
      `CREATE TABLE "LoginAttempt" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "email" character varying NOT NULL, "success" boolean NOT NULL, "timestamp" TIMESTAMP NOT NULL DEFAULT now(), "ipAddress" character varying, CONSTRAINT "PK_371789a3ceedc1191a72af39ae9" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_4e716463f9b772e41ca24b953d" ON "LoginAttempt" ("email") `
    );
    await queryRunner.query(
      `CREATE TABLE "query-result-cache" ("id" SERIAL NOT NULL, "identifier" character varying, "time" bigint NOT NULL, "duration" integer NOT NULL, "query" text NOT NULL, "result" text NOT NULL, CONSTRAINT "PK_6a98f758d8bfd010e7e10ffd3d3" PRIMARY KEY ("id"))`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE "query-result-cache"`);
    await queryRunner.query(
      `DROP INDEX "public"."IDX_4e716463f9b772e41ca24b953d"`
    );
    await queryRunner.query(`DROP TABLE "LoginAttempt"`);
    await queryRunner.query(
      `DROP INDEX "public"."IDX_13f3208a3c2802d86170be9235"`
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_d8a2b91d7d64904668d2f1b517"`
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_662d4382153fd190df048bf0f6"`
    );
    await queryRunner.query(`DROP TABLE "Token"`);
    await queryRunner.query(`DROP TYPE "public"."Token_tokentype_enum"`);
    await queryRunner.query(
      `DROP INDEX "public"."IDX_9d3bf2db7fa484cefa22cfcd53"`
    );
    await queryRunner.query(`DROP TABLE "ActivityLog"`);
    await queryRunner.query(`DROP TYPE "public"."ActivityLog_event_enum"`);
    await queryRunner.query(
      `DROP INDEX "public"."IDX_2db8a9718a1161eb428827faba"`
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_f54a403562686cddb1a025fea8"`
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_dc1618bce8f5b8a05b1de99bf2"`
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_f0a3247774bd4eaad217705533"`
    );
    await queryRunner.query(`DROP TABLE "Device"`);
    await queryRunner.query(
      `DROP INDEX "public"."IDX_4a257d2c9837248d70640b3e36"`
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_9862f679340fb2388436a5ab3e"`
    );
    await queryRunner.query(`DROP TABLE "User"`);
    await queryRunner.query(`DROP TYPE "public"."User_approle_enum"`);
  }
}
