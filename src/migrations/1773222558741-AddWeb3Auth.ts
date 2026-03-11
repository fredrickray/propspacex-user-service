import { MigrationInterface, QueryRunner } from "typeorm";

export class AddWeb3Auth1773222558741 implements MigrationInterface {
    name = 'AddWeb3Auth1773222558741'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "Wallet" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "walletAddress" character varying NOT NULL, "userId" character varying NOT NULL, "isPrimary" boolean NOT NULL DEFAULT true, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "PK_8828fa4047435abf9287ff0e89e" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE UNIQUE INDEX "IDX_960e518bb36c9791b971d08f18" ON "Wallet" ("walletAddress") `);
        await queryRunner.query(`CREATE INDEX "IDX_2f7aa51d6746fc8fc8ed63ddfb" ON "Wallet" ("userId") `);
        await queryRunner.query(`CREATE TABLE "WalletNonce" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "walletAddress" character varying NOT NULL, "nonce" character varying NOT NULL, "expiresAt" TIMESTAMP NOT NULL, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "PK_60066996496919d83f3f8eef6d7" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "IDX_2d33b7b8d59fc94d7767903fa5" ON "WalletNonce" ("walletAddress") `);
        await queryRunner.query(`CREATE TYPE "public"."User_authmethod_enum" AS ENUM('email', 'wallet', 'both')`);
        await queryRunner.query(`ALTER TABLE "User" ADD "authMethod" "public"."User_authmethod_enum" NOT NULL DEFAULT 'email'`);
        await queryRunner.query(`ALTER TABLE "User" ALTER COLUMN "password" DROP NOT NULL`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "User" ALTER COLUMN "password" SET NOT NULL`);
        await queryRunner.query(`ALTER TABLE "User" DROP COLUMN "authMethod"`);
        await queryRunner.query(`DROP TYPE "public"."User_authmethod_enum"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_2d33b7b8d59fc94d7767903fa5"`);
        await queryRunner.query(`DROP TABLE "WalletNonce"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_2f7aa51d6746fc8fc8ed63ddfb"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_960e518bb36c9791b971d08f18"`);
        await queryRunner.query(`DROP TABLE "Wallet"`);
    }

}
