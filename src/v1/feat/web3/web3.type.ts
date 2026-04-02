export interface IRequestNonce {
  walletAddress: string;
  appRole?: string;
}

export interface IVerifySignature {
  walletAddress: string;
  signature: string;
  message: string;
}

export interface IWallet {
  id: string;
  walletAddress: string;
  userId: string;
  isPrimary: boolean;
  createdAt: Date;
}

export interface IWalletNonce {
  id: string;
  walletAddress: string;
  nonce: string;
  expiresAt: Date;
  createdAt: Date;
}
