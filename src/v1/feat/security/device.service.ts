import { AppDataSource } from '@config/data.source';
import { Device } from './device.entity';
import { generateRandomHexString } from '@utils/crypto.utils';
import geoip from 'geoip-lite';

const deviceRepo = AppDataSource.getRepository(Device);

export default class DeviceService {
  static async registerOrUpdate(
    userId: string,
    ipAddress?: string,
    userAgent?: string,
    opts?: { isTrusted?: boolean }
  ) {
    const existing = await deviceRepo.findOne({
      where: { userId, userAgent, ipAddress },
    });
    if (existing) {
      existing.lastActive = new Date();
      if (opts?.isTrusted !== undefined) existing.isTrusted = !!opts.isTrusted;
      return await deviceRepo.save(existing);
    }
    const deviceId = generateRandomHexString(32);
    const deviceType = DeviceService.detectDeviceType(userAgent);
    const location = ipAddress
      ? DeviceService.lookupLocation(ipAddress)
      : undefined;

    const device = deviceRepo.create({
      userId,
      deviceId,
      deviceType,
      ipAddress: ipAddress ?? '',
      userAgent: userAgent ?? '',
      location, // Now it's string | undefined instead of string | null
      isTrusted: !!opts?.isTrusted,
      isRevoked: false,
      firstLogin: new Date(),
      lastActive: new Date(),
    });
    return await deviceRepo.save(device);
  }
  static detectDeviceType(userAgent?: string): string {
    if (!userAgent) return 'Unknown';
    const ua = userAgent.toLowerCase();
    // Mobile devices
    if (ua.includes('mobile') || ua.includes('android')) return 'Mobile';
    if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ipod'))
      return 'Mobile';
    // Tablets
    if (ua.includes('tablet') || ua.includes('ipad')) return 'Tablet';
    // Desktop
    if (
      ua.includes('windows') ||
      ua.includes('macintosh') ||
      ua.includes('linux')
    )
      return 'Desktop';
    return 'Unknown';
  }
  static lookupLocation(ip?: string): string | undefined {
    if (!ip) return undefined;
    try {
      const geo = geoip.lookup(ip);
      if (!geo) return undefined;
      return [geo.city, geo.region, geo.country].filter(Boolean).join(', ');
    } catch (e) {
      return undefined;
    }
  }
  static async revokeDevice(userId: string, deviceId: string) {
    const device = await deviceRepo.findOneBy({ userId, deviceId });
    if (!device) return null;
    device.isRevoked = true;
    return await deviceRepo.save(device);
  }
  static async listDevicesForUser(userId: string) {
    return deviceRepo.find({
      where: { userId },
      order: { lastActive: 'DESC' },
    });
  }
}
