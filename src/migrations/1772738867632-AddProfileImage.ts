import { MigrationInterface, QueryRunner } from "typeorm";

export class AddProfileImage1772738867632 implements MigrationInterface {
    name = 'AddProfileImage1772738867632'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "User" ADD "profileImage" jsonb`);
        await queryRunner.query(`ALTER TABLE "User" ADD "reAuth" boolean NOT NULL DEFAULT false`);
        await queryRunner.query(`ALTER TABLE "User" ADD "tokenVersion" integer NOT NULL DEFAULT '0'`);
        await queryRunner.query(`ALTER TABLE "User" ADD "updatedAt" TIMESTAMP`);
        await queryRunner.query(`CREATE INDEX "IDX_9862f679340fb2388436a5ab3e" ON "User" ("id") `);
        await queryRunner.query(`CREATE INDEX "IDX_4a257d2c9837248d70640b3e36" ON "User" ("email") `);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP INDEX "public"."IDX_4a257d2c9837248d70640b3e36"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_9862f679340fb2388436a5ab3e"`);
        await queryRunner.query(`ALTER TABLE "User" DROP COLUMN "updatedAt"`);
        await queryRunner.query(`ALTER TABLE "User" DROP COLUMN "tokenVersion"`);
        await queryRunner.query(`ALTER TABLE "User" DROP COLUMN "reAuth"`);
        await queryRunner.query(`ALTER TABLE "User" DROP COLUMN "profileImage"`);
    }

}
