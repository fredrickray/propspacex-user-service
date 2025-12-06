import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddIndexes1767300335463 implements MigrationInterface {
  name = 'AddIndexes1767300335463';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE INDEX "IDX_4a257d2c9837248d70640b3e36" ON "User" ("email") `
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
      `CREATE INDEX "IDX_662d4382153fd190df048bf0f6" ON "Token" ("userId") `
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_d8a2b91d7d64904668d2f1b517" ON "Token" ("tokenType") `
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_13f3208a3c2802d86170be9235" ON "Token" ("userId", "tokenType") `
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
    await queryRunner.query(
      `DROP INDEX "public"."IDX_13f3208a3c2802d86170be9235"`
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_d8a2b91d7d64904668d2f1b517"`
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_662d4382153fd190df048bf0f6"`
    );
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
      `DROP INDEX "public"."IDX_4a257d2c9837248d70640b3e36"`
    );
  }
}
