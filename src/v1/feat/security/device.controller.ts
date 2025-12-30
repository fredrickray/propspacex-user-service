import { Request, Response } from 'express';
import DeviceService from './device.service';
import { extractClientInfo } from '@utils/request.utils';
import { Unauthorized } from '@middlewares/error.middleware';

export default class DeviceController {
  static async listDevices(req: Request, res: Response) {
    try {
      const userId = req.authUser?.id;
      if (!userId) throw new Unauthorized('Authentication required');

      const devices = await DeviceService.listDevicesForUser(userId);

      res.status(200).json({
        success: true,
        data: devices,
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        message: error.message,
      });
    }
  }
  static async trustDevice(req: Request, res: Response) {
    try {
      const userId = req.authUser?.id;
      if (!userId) throw new Unauthorized('Authentication required');
      const { deviceId } = req.params;

      const device = await DeviceService.trustDevice(userId, deviceId);

      res.status(200).json({
        success: true,
        message: 'Device trusted successfully',
        data: device,
      });
    } catch (error: any) {
      res.status(400).json({
        success: false,
        message: error.message,
      });
    }
  }

  static async revokeDevice(req: Request, res: Response) {
    try {
      const userId = req.authUser?.id;
      if (!userId) throw new Unauthorized('Authentication required');
      const { deviceId } = req.params;

      const device = await DeviceService.revokeDevice(userId, deviceId);

      res.status(200).json({
        success: true,
        message: 'Device revoked successfully',
        data: device,
      });
    } catch (error: any) {
      res.status(400).json({
        success: false,
        message: error.message,
      });
    }
  }

  static async getTrustedDevices(req: Request, res: Response) {
    try {
      const userId = req.authUser?.id;
      if (!userId) throw new Unauthorized('Authentication required');

      const devices = await DeviceService.getTrustedDevices(userId);

      res.status(200).json({
        success: true,
        data: devices,
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        message: error.message,
      });
    }
  }
}
