import { Request, Response, NextFunction } from 'express';
import Web3Service from './web3.service';
import { extractClientInfo } from '@utils/request.utils';

export default class Web3Controller {
  /**
   * POST /v1/api/web3/nonce
   * Request a nonce for wallet authentication.
   */
  static async requestNonce(req: Request, res: Response, next: NextFunction) {
    try {
      const { walletAddress } = req.body;

      const { nonce, message } = await Web3Service.requestNonce(walletAddress);

      res.status(200).json({
        success: true,
        message: 'Nonce generated successfully',
        data: { nonce, message },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * POST /v1/api/web3/verify
   * Verify wallet signature and authenticate.
   */
  static async verifySignature(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    try {
      const { walletAddress, signature, message } = req.body;
      const { ipAddress, userAgent, location } = extractClientInfo(req);

      const { accessToken, refreshToken, user, device } =
        await Web3Service.verifySignature(
          walletAddress,
          signature,
          message,
          ipAddress,
          userAgent,
          location
        );

      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('at', accessToken);
      res.setHeader('rt', refreshToken);

      res.status(200).json({
        success: true,
        message: 'Wallet authentication successful',
        data: {
          accessToken,
          refreshToken,
          user: {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            appRole: user.appRole,
            authMethod: user.authMethod,
            isVerified: user.isVerified,
          },
          device: {
            deviceId: device.deviceId,
            deviceType: device.deviceType,
            location: device.location,
            isTrusted: device.isTrusted,
            lastActive: device.lastActive,
          },
        },
      });
    } catch (error) {
      console.error(error);
      next(error);
    }
  }

  /**
   * POST /v1/api/web3/link
   * Link a wallet to an existing authenticated user.
   */
  static async linkWallet(req: Request, res: Response, next: NextFunction) {
    try {
      const { walletAddress } = req.body;
      const userId = (req as any).user?.sub;

      if (!userId) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required to link a wallet',
        });
      }

      const wallet = await Web3Service.linkWallet(userId, walletAddress);

      res.status(201).json({
        success: true,
        message: 'Wallet linked successfully',
        data: {
          walletAddress: wallet.walletAddress,
          isPrimary: wallet.isPrimary,
        },
      });
    } catch (error) {
      next(error);
    }
  }
}
