import { Entity, PrimaryGeneratedColumn, Column, Index } from 'typeorm';
import { AppRoles } from './user.type';
// import { AppDataSource } from '@config/data.source';

@Entity('User')
export class User {
  @Index()
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'varchar' })
  firstName!: string;

  @Column({ type: 'varchar' })
  lastName!: string;

  @Index()
  @Column({ type: 'varchar', unique: true })
  email!: string;

  @Column({ type: 'varchar' })
  password!: string;

  @Column({ type: 'jsonb', nullable: true })
  profileImage!: {
    url: string;
    mediaId: string;
  };

  @Column({ type: 'enum', enum: AppRoles, default: AppRoles.BUYER })
  appRole!: AppRoles;

  @Column({ type: 'boolean', default: false })
  isVerified!: boolean;

  @Column({ type: 'boolean', default: false })
  reAuth!: boolean;

  @Column({ type: 'int', default: 0 })
  tokenVersion!: number;

  @Column({ type: 'boolean', default: true })
  isAccountActive!: boolean;

  @Column({ type: 'timestamp', nullable: true })
  lastLoginDate!: Date;

  @Column({ type: 'int', default: 0 })
  loginAttempts!: number;

  @Column({ type: 'int', default: 5 })
  allowedLoginAttempts!: number;

  @Column({ type: 'timestamp', nullable: true })
  loginCooldown!: Date;

  @Column({ type: 'timestamp', nullable: true })
  createdAt!: Date;

  @Column({ type: 'timestamp', nullable: true })
  updatedAt!: Date;
}

// export const userRepo = AppDataSource.getRepository(User);
