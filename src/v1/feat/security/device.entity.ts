import { Entity, PrimaryGeneratedColumn, Column, Index } from 'typeorm';
import { AppDataSource } from '@config/data.source';

@Entity('Device')
@Index(['userId', 'deviceId']) // Composite index for common queries
export class Device {
  @Index()
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index()
  @Column({ type: 'varchar' })
  userId!: string;

  @Index()
  @Column({ type: 'varchar' })
  deviceId!: string;

  @Column({ type: 'varchar' })
  deviceType!: string;

  @Column({ type: 'varchar' })
  ipAddress!: string;

  @Column({ type: 'text' })
  userAgent!: string;

  @Column({ type: 'varchar', nullable: true })
  location!: string; // e.g. Lagos, Nigeria

  @Column({ type: 'boolean', default: false })
  isTrusted!: boolean;

  @Column({ type: 'boolean', default: false })
  isRevoked!: boolean;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  firstLogin!: Date;

  @Column({ type: 'timestamp', nullable: true })
  lastActive!: Date;
}

// export const deviceRepo = AppDataSource.getRepository(Device);
