import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddChat1773500000000 implements MigrationInterface {
  name = 'AddChat1773500000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TYPE "public"."Conversation_status_enum" AS ENUM('active', 'archived', 'closed')`
    );
    await queryRunner.query(
      `CREATE TABLE "Conversation" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "buyerId" uuid NOT NULL, "agentId" uuid NOT NULL, "propertyId" uuid, "status" "public"."Conversation_status_enum" NOT NULL DEFAULT 'active', "lastMessageAt" TIMESTAMP, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "PK_45dd9f7f5f35ec4a12d0102f2e7" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `CREATE UNIQUE INDEX "IDX_e498fcaef8d9be34ba9a18de8c" ON "Conversation" ("buyerId", "agentId", "propertyId")`
    );
    await queryRunner.query(
      `CREATE UNIQUE INDEX "IDX_Conversation_direct_unique" ON "Conversation" ("buyerId", "agentId") WHERE "propertyId" IS NULL`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_8cae1268dd44df16edf4368d88" ON "Conversation" ("buyerId")`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_89e68fd0f73e99f8db1dd4cc7f" ON "Conversation" ("agentId")`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_a1e718a7cc2ac3fe9464f11ad8" ON "Conversation" ("propertyId")`
    );
    await queryRunner.query(
      `CREATE TYPE "public"."Message_messagetype_enum" AS ENUM('text')`
    );
    await queryRunner.query(
      `CREATE TABLE "Message" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "conversationId" uuid NOT NULL, "senderId" uuid NOT NULL, "recipientId" uuid NOT NULL, "messageType" "public"."Message_messagetype_enum" NOT NULL DEFAULT 'text', "body" text NOT NULL, "metadata" jsonb, "readAt" TIMESTAMP, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "PK_b4a92f3d4d7e4a5f13f2f5f8dbe" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_b9025ec849fb5f57c8da4ca3bf" ON "Message" ("conversationId", "createdAt")`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_4ad813bfd96f6aaecf0f23f7d6" ON "Message" ("senderId")`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_1d92595bf2f2298f09c0d053f4" ON "Message" ("recipientId")`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_a36ef2d1967632d4f4eb6ab4f2" ON "Message" ("conversationId", "recipientId", "readAt")`
    );
    await queryRunner.query(
      `ALTER TABLE "Conversation" ADD CONSTRAINT "FK_c65fd20f60e95a4a67850a8c597" FOREIGN KEY ("buyerId") REFERENCES "User"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`
    );
    await queryRunner.query(
      `ALTER TABLE "Conversation" ADD CONSTRAINT "FK_6d545fd8910f910f82bdf95f7cb" FOREIGN KEY ("agentId") REFERENCES "User"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`
    );
    await queryRunner.query(
      `ALTER TABLE "Message" ADD CONSTRAINT "FK_a4de1b716d8c7af36df10f5fdda" FOREIGN KEY ("conversationId") REFERENCES "Conversation"("id") ON DELETE CASCADE ON UPDATE NO ACTION`
    );
    await queryRunner.query(
      `ALTER TABLE "Message" ADD CONSTRAINT "FK_f6819af783d76ec61f0d5ed3018" FOREIGN KEY ("senderId") REFERENCES "User"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`
    );
    await queryRunner.query(
      `ALTER TABLE "Message" ADD CONSTRAINT "FK_5f458adb4d01d2f9f43f880f6ef" FOREIGN KEY ("recipientId") REFERENCES "User"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "Message" DROP CONSTRAINT "FK_5f458adb4d01d2f9f43f880f6ef"`
    );
    await queryRunner.query(
      `ALTER TABLE "Message" DROP CONSTRAINT "FK_f6819af783d76ec61f0d5ed3018"`
    );
    await queryRunner.query(
      `ALTER TABLE "Message" DROP CONSTRAINT "FK_a4de1b716d8c7af36df10f5fdda"`
    );
    await queryRunner.query(
      `ALTER TABLE "Conversation" DROP CONSTRAINT "FK_6d545fd8910f910f82bdf95f7cb"`
    );
    await queryRunner.query(
      `ALTER TABLE "Conversation" DROP CONSTRAINT "FK_c65fd20f60e95a4a67850a8c597"`
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_a36ef2d1967632d4f4eb6ab4f2"`
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_1d92595bf2f2298f09c0d053f4"`
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_4ad813bfd96f6aaecf0f23f7d6"`
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_b9025ec849fb5f57c8da4ca3bf"`
    );
    await queryRunner.query(`DROP TABLE "Message"`);
    await queryRunner.query(`DROP TYPE "public"."Message_messagetype_enum"`);
    await queryRunner.query(
      `DROP INDEX "public"."IDX_a1e718a7cc2ac3fe9464f11ad8"`
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_89e68fd0f73e99f8db1dd4cc7f"`
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_8cae1268dd44df16edf4368d88"`
    );
    await queryRunner.query(`DROP INDEX "public"."IDX_Conversation_direct_unique"`);
    await queryRunner.query(
      `DROP INDEX "public"."IDX_e498fcaef8d9be34ba9a18de8c"`
    );
    await queryRunner.query(`DROP TABLE "Conversation"`);
    await queryRunner.query(`DROP TYPE "public"."Conversation_status_enum"`);
  }
}
