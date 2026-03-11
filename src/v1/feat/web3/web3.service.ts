import { ethers } from 'ethers';
import crypto from 'crypto';
import { AppDataSource } from '@config/data.source';
import { User } from '@user/user.entity';
import { Wallet, WalletNonce } from './web3.entity';
import { AuthMethod } from '@user/user.type';
import { AppRoles } from '@user/user.type';
import AuthService from '@auth/auth.service';
import {
  BadRequest,
  ResourceNotFound,
  Unauthorized,
} from '@middlewares/error.middleware';
import {
  requestNonceValidationSchema,
  verifySignatureValidationSchema,
} from '@validations/web3.validations';
import { InvalidInput } from '@middlewares/error.middleware';
import DeviceService from '@security/device.service';
import ActivityService from '@security/activity.service';
import { Event } from '@security/activity.type';

const userRepo = AppDataSource.getRepository(User);
const walletRepo = AppDataSource.getRepository(Wallet);
const nonceRepo = AppDataSource.getRepository(WalletNonce);

const NONCE_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes

export default class Web3Service {
  /**
   * Generate a nonce for wallet authentication.
   * If no user/wallet exists, creates one on the fly.
   */
  static async requestNonce(walletAddress: string) {
    // Validate input
    const { error } = requestNonceValidationSchema.validate({ walletAddress });
    if (error) {
      throw new InvalidInput(
        error.details.map((d) => d.message).join(', ')
      );
    }

    // Normalize the address to checksum format
    const normalizedAddress = ethers.getAddress(walletAddress);

    // Find existing wallet or create new user + wallet
    let wallet = await walletRepo.findOneBy({
      walletAddress: normalizedAddress,
    });

    if (!wallet) {
      // Create a new user for this wallet
      const newUser = userRepo.create({
        firstName: 'Wallet User',
        lastName: '',
        email: `${normalizedAddress.toLowerCase()}@wallet.local`,
        authMethod: AuthMethod.WALLET,
        isVerified: true, // Wallet users are verified by default
        appRole: AppRoles.BUYER,
      });
      await userRepo.save(newUser);

      // Create the wallet record
      wallet = walletRepo.create({
        walletAddress: normalizedAddress,
        userId: newUser.id,
        isPrimary: true,
      });
      await walletRepo.save(wallet);
    }

    // Delete any existing nonces for this address
    await nonceRepo.delete({ walletAddress: normalizedAddress });

    // Generate a new nonce
    const nonce = crypto.randomBytes(32).toString('hex');

    // Store nonce with expiry
    await nonceRepo.save(
      nonceRepo.create({
        walletAddress: normalizedAddress,
        nonce,
        expiresAt: new Date(Date.now() + NONCE_EXPIRY_MS),
      })
    );

    // Build SIWE-style message
    const message = this.buildSignMessage(normalizedAddress, nonce);

    return { nonce, message };
  }

  /**
   * Verify a wallet signature and return JWT tokens.
   */
  static async verifySignature(
    walletAddress: string,
    signature: string,
    message: string,
    ipAddress?: string,
    userAgent?: string,
    location?: string
  ) {
    // Validate input
    const { error } = verifySignatureValidationSchema.validate({
      walletAddress,
      signature,
      message,
    });
    if (error) {
      throw new InvalidInput(
        error.details.map((d) => d.message).join(', ')
      );
    }

    const normalizedAddress = ethers.getAddress(walletAddress);

    // Recover the signer address from the signature
    let recoveredAddress: string;
    try {
      recoveredAddress = ethers.verifyMessage(message, signature);
    } catch {
      throw new Unauthorized('Invalid signature');
    }

    // Check that the recovered address matches the claimed address
    if (recoveredAddress.toLowerCase() !== normalizedAddress.toLowerCase()) {
      throw new Unauthorized(
        'Signature does not match the provided wallet address'
      );
    }

    // Find and validate the nonce
    const storedNonce = await nonceRepo.findOneBy({
      walletAddress: normalizedAddress,
    });

    if (!storedNonce) {
      throw new BadRequest(
        'No nonce found for this address. Please request a new nonce.'
      );
    }

    // Check nonce expiry
    if (new Date() > storedNonce.expiresAt) {
      await nonceRepo.delete({ id: storedNonce.id });
      throw new Unauthorized('Nonce has expired. Please request a new one.');
    }

    // Verify the nonce is embedded in the message
    if (!message.includes(storedNonce.nonce)) {
      throw new Unauthorized('Invalid nonce in message');
    }

    // Delete the used nonce (one-time use)
    await nonceRepo.delete({ id: storedNonce.id });

    // Find the wallet and associated user
    const wallet = await walletRepo.findOneBy({
      walletAddress: normalizedAddress,
    });
    if (!wallet) {
      throw new ResourceNotFound('Wallet not found');
    }

    const user = await userRepo.findOneBy({ id: wallet.userId });
    if (!user) {
      throw new ResourceNotFound('User associated with wallet not found');
    }

    // Update last login
    user.lastLoginDate = new Date();
    await userRepo.save(user);

    // Register device
    const { device } = await DeviceService.registerOrUpdate(
      user.id,
      ipAddress,
      userAgent,
      { isTrusted: false }
    );

    // Log activity (fire-and-forget)
    ActivityService.log(Event.LOGIN_SUCCESS, {
      userId: user.id,
      ip: ipAddress,
      userAgent,
      location,
      deviceId: device.deviceId,
      metadata: {
        authMethod: 'wallet',
        walletAddress: normalizedAddress,
        deviceType: device.deviceType,
      },
    }).catch((err) => console.error('Activity log error:', err));

    // Generate JWT tokens (reuse existing AuthService)
    const { accessToken, refreshToken } =
      await AuthService.generateTokens(user);

    return { accessToken, refreshToken, user, device };
  }

  /**
   * Link a wallet to an existing user account.
   */
  static async linkWallet(userId: string, walletAddress: string) {
    const { error } = requestNonceValidationSchema.validate({ walletAddress });
    if (error) {
      throw new InvalidInput(
        error.details.map((d) => d.message).join(', ')
      );
    }

    const normalizedAddress = ethers.getAddress(walletAddress);

    // Check if wallet is already linked
    const existingWallet = await walletRepo.findOneBy({
      walletAddress: normalizedAddress,
    });
    if (existingWallet) {
      throw new BadRequest('This wallet is already linked to an account');
    }

    // Check if user exists
    const user = await userRepo.findOneBy({ id: userId });
    if (!user) {
      throw new ResourceNotFound('User not found');
    }

    // Check if user already has wallets
    const userWallets = await walletRepo.findBy({ userId });
    const isPrimary = userWallets.length === 0;

    // Create wallet link
    const wallet = walletRepo.create({
      walletAddress: normalizedAddress,
      userId,
      isPrimary,
    });
    await walletRepo.save(wallet);

    // Update auth method if user was email-only
    if (user.authMethod === AuthMethod.EMAIL) {
      user.authMethod = AuthMethod.BOTH;
      await userRepo.save(user);
    }

    return wallet;
  }

  /**
   * Build a human-readable sign message (SIWE-style).
   */
  private static buildSignMessage(
    walletAddress: string,
    nonce: string
  ): string {
    return [
      'Welcome to PropSpaceX!',
      '',
      'Please sign this message to verify your wallet ownership.',
      '',
      `Wallet: ${walletAddress}`,
      `Nonce: ${nonce}`,
      `Issued At: ${new Date().toISOString()}`,
    ].join('\n');
  }
}
