import { Entity, PrimaryGeneratedColumn, Column, Index } from 'typeorm';
import { TokenType } from './auth.type';

@Entity('Token')
@Index(['userId', 'tokenType']) // Composite index for common queries
export class Token {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index()
  @Column({ type: 'varchar' })
  userId!: string;

  @Column({ type: 'varchar' })
  token!: string;

  @Index()
  @Column({ type: 'enum', enum: TokenType })
  tokenType!: TokenType;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt!: Date;

  @Column({ type: 'timestamp', nullable: true })
  expiresAt!: Date;
}

@Entity('LoginAttempt')
export class LoginAttempt {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index()
  @Column({ type: 'varchar' })
  email!: string;

  @Column({ type: 'boolean' })
  success!: boolean;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  timestamp!: Date;

  @Column({ type: 'varchar', nullable: true })
  ipAddress!: string;
}
