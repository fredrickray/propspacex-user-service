import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddDealSource1773700000000 implements MigrationInterface {
  name = 'AddDealSource1773700000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "Deal" ADD "source" character varying NOT NULL DEFAULT 'website'`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "Deal" DROP COLUMN "source"`);
  }
}
