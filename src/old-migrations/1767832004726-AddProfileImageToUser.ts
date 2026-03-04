import { MigrationInterface, QueryRunner } from "typeorm";

export class AddProfileImageToUser1767832004726 implements MigrationInterface {
    name = 'AddProfileImageToUser1767832004726'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "User" ADD "profileImage" jsonb`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "User" DROP COLUMN "profileImage"`);
    }

}
