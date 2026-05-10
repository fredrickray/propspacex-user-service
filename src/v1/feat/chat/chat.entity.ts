import {
  Column,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  OneToMany,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { ConversationStatus, MessageType } from './chat.type';
import { User } from '@user/user.entity';

@Entity('Conversation')
@Index(['buyerId', 'agentId', 'propertyId'], { unique: true })
@Index('IDX_Conversation_direct_unique', ['buyerId', 'agentId'], {
  unique: true,
  where: '"propertyId" IS NULL',
})
@Index(['buyerId'])
@Index(['agentId'])
@Index(['propertyId'])
export class Conversation {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid' })
  buyerId!: string;

  @Column({ type: 'uuid' })
  agentId!: string;

  @Column({ type: 'uuid', nullable: true })
  propertyId!: string | null;

  @Column({
    type: 'enum',
    enum: ConversationStatus,
    default: ConversationStatus.ACTIVE,
  })
  status!: ConversationStatus;

  @Column({ type: 'timestamp', nullable: true })
  lastMessageAt!: Date | null;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt!: Date;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updatedAt!: Date;

  @ManyToOne(() => User, { nullable: false })
  @JoinColumn({ name: 'buyerId' })
  buyer!: User;

  @ManyToOne(() => User, { nullable: false })
  @JoinColumn({ name: 'agentId' })
  agent!: User;

  @OneToMany(() => Message, (message) => message.conversation)
  messages!: Message[];
}

@Entity('Message')
@Index(['conversationId', 'createdAt'])
@Index(['senderId'])
@Index(['recipientId'])
@Index(['conversationId', 'recipientId', 'readAt'])
export class Message {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid' })
  conversationId!: string;

  @Column({ type: 'uuid' })
  senderId!: string;

  @Column({ type: 'uuid' })
  recipientId!: string;

  @Column({ type: 'enum', enum: MessageType, default: MessageType.TEXT })
  messageType!: MessageType;

  @Column({ type: 'text' })
  body!: string;

  @Column({ type: 'jsonb', nullable: true })
  metadata!: Record<string, any> | null;

  @Column({ type: 'timestamp', nullable: true })
  readAt!: Date | null;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt!: Date;

  @ManyToOne(() => Conversation, (conversation) => conversation.messages, {
    nullable: false,
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'conversationId' })
  conversation!: Conversation;

  @ManyToOne(() => User, { nullable: false })
  @JoinColumn({ name: 'senderId' })
  sender!: User;

  @ManyToOne(() => User, { nullable: false })
  @JoinColumn({ name: 'recipientId' })
  recipient!: User;
}
