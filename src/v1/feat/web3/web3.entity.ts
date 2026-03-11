import { Entity, PrimaryGeneratedColumn, Column, Index } from 'typeorm';

@Entity('Wallet')
@Index(['userId'])
export class Wallet {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index({ unique: true })
  @Column({ type: 'varchar' })
  walletAddress!: string;

  @Index()
  @Column({ type: 'varchar' })
  userId!: string;

  @Column({ type: 'boolean', default: true })
  isPrimary!: boolean;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt!: Date;
}

@Entity('WalletNonce')
@Index(['walletAddress'])
export class WalletNonce {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'varchar' })
  walletAddress!: string;

  @Column({ type: 'varchar' })
  nonce!: string;

  @Column({ type: 'timestamp' })
  expiresAt!: Date;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt!: Date;
}
