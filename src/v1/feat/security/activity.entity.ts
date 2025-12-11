import { Entity, PrimaryGeneratedColumn, Column, Index } from 'typeorm';
import { Event } from './activity.type';

@Entity('ActivityLog')
export class ActivityLog {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index()
  @Column({ type: 'varchar', nullable: true })
  userId!: string | null;

  @Column({ type: 'enum', enum: Event })
  event!: Event;

  @Column({ type: 'varchar', nullable: true })
  ip!: string | null;

  @Column({ type: 'text', nullable: true })
  userAgent!: string | null;

  @Column({ type: 'varchar', nullable: true })
  location!: string | null;

  @Column({ type: 'varchar', nullable: true })
  deviceId!: string | null;

  @Column({ type: 'text', nullable: true })
  metadata!: string | null; // optional structured JSON string for future use

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  timestamp!: Date;
}
