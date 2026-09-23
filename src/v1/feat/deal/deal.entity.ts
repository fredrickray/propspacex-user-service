import {
  Column,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { Conversation } from '@chat/chat.entity';
import { User } from '@user/user.entity';
import { DealStatus } from './deal.type';

@Entity('Deal')
@Index(['conversationId'], { unique: true })
@Index(['buyerId'])
@Index(['agentId'])
@Index(['status'])
export class Deal {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid' })
  conversationId!: string;

  @Column({ type: 'uuid', nullable: true })
  propertyId!: string | null;

  @Column({ type: 'varchar', nullable: true })
  propertyTitle!: string | null;

  @Column({ type: 'uuid' })
  buyerId!: string;

  @Column({ type: 'uuid' })
  agentId!: string;

  @Column({
    type: 'enum',
    enum: DealStatus,
    default: DealStatus.OPEN,
  })
  status!: DealStatus;

  @Column({ type: 'bigint', nullable: true })
  quotedAmountMinor!: number | null;

  @Column({ type: 'bigint', nullable: true })
  platformFeeMinor!: number | null;

  @Column({ type: 'text', nullable: true })
  quoteNote!: string | null;

  @Column({ type: 'uuid', nullable: true })
  escrowId!: string | null;

  @Column({ type: 'timestamp', nullable: true })
  quotedAt!: Date | null;

  @Column({ type: 'timestamp', nullable: true })
  acceptedAt!: Date | null;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt!: Date;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updatedAt!: Date;

  @ManyToOne(() => Conversation, { nullable: false })
  @JoinColumn({ name: 'conversationId' })
  conversation!: Conversation;

  @ManyToOne(() => User, { nullable: false })
  @JoinColumn({ name: 'buyerId' })
  buyer!: User;

  @ManyToOne(() => User, { nullable: false })
  @JoinColumn({ name: 'agentId' })
  agent!: User;
}
