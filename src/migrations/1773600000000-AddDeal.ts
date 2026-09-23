import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddDeal1773600000000 implements MigrationInterface {
  name = 'AddDeal1773600000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TYPE "public"."Deal_status_enum" AS ENUM('open', 'quoted', 'funding_ready', 'in_progress', 'pending_buyer_release', 'released', 'cancelled', 'disputed', 'refunded')`
    );
    await queryRunner.query(
      `CREATE TABLE "Deal" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "conversationId" uuid NOT NULL, "propertyId" uuid, "propertyTitle" character varying, "buyerId" uuid NOT NULL, "agentId" uuid NOT NULL, "status" "public"."Deal_status_enum" NOT NULL DEFAULT 'open', "quotedAmountMinor" bigint, "platformFeeMinor" bigint, "quoteNote" text, "escrowId" uuid, "quotedAt" TIMESTAMP, "acceptedAt" TIMESTAMP, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "PK_7466be4dd8d1f32dcf5e9d8e201" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `CREATE UNIQUE INDEX "IDX_dcb5f7d20f94d9e5c7f4e3b8bb" ON "Deal" ("conversationId")`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_986a8cf8ed11fe8f95b9fd80cf" ON "Deal" ("buyerId")`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_f2fba67ddd268f8ea11ea37f41" ON "Deal" ("agentId")`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_2cf210ea1d7f3707ea4c4f7f95" ON "Deal" ("status")`
    );
    await queryRunner.query(
      `ALTER TABLE "Deal" ADD CONSTRAINT "FK_86d90d7826802ad5d5754516c38" FOREIGN KEY ("conversationId") REFERENCES "Conversation"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`
    );
    await queryRunner.query(
      `ALTER TABLE "Deal" ADD CONSTRAINT "FK_12d28038d5c067f3428dbaf425d" FOREIGN KEY ("buyerId") REFERENCES "User"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`
    );
    await queryRunner.query(
      `ALTER TABLE "Deal" ADD CONSTRAINT "FK_f84f1f2ac8f4a4f54f2d2ee9969" FOREIGN KEY ("agentId") REFERENCES "User"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "Deal" DROP CONSTRAINT "FK_f84f1f2ac8f4a4f54f2d2ee9969"`
    );
    await queryRunner.query(
      `ALTER TABLE "Deal" DROP CONSTRAINT "FK_12d28038d5c067f3428dbaf425d"`
    );
    await queryRunner.query(
      `ALTER TABLE "Deal" DROP CONSTRAINT "FK_86d90d7826802ad5d5754516c38"`
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_2cf210ea1d7f3707ea4c4f7f95"`
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_f2fba67ddd268f8ea11ea37f41"`
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_986a8cf8ed11fe8f95b9fd80cf"`
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_dcb5f7d20f94d9e5c7f4e3b8bb"`
    );
    await queryRunner.query(`DROP TABLE "Deal"`);
    await queryRunner.query(`DROP TYPE "public"."Deal_status_enum"`);
  }
}
