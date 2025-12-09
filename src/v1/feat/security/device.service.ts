import { AppDataSource } from '@config/data.source';
import { Device } from './device.entity';
import { generateRandomHexString } from '@utils/crypto.utils';
import geoip from 'geoip-lite';
import ActivityService from './activity.service';
import { Event } from './activity.type';
import SecurityAlertService from './security-alert.service';
import { ResourceNotFound } from '@middlewares/error.middleware';

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

    const savedDevice = await deviceRepo.save(device);

    await this.checkForSuspiciousDevice(userId, savedDevice);

    return savedDevice;
  }

  static async trustDevice(userId: string, deviceId: string) {
    const device = await deviceRepo.findOne({
      where: { userId, deviceId, isRevoked: false },
    });

    if (!device) {
      throw new Error('Device not found or already revoked');
    }

    device.isTrusted = true;
    await deviceRepo.save(device);

    await ActivityService.log(Event.DEVICE_TRUSTED, {
      userId,
      deviceId,
      ip: device.ipAddress || undefined,
      userAgent: device.userAgent || undefined,
      location: device.location || undefined,
      metadata: {
        deviceType: device.deviceType,
      },
    });

    return device;
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
    const device = await deviceRepo.findOne({ where: { userId, deviceId } });
    if (!device) throw new ResourceNotFound('Device not found');

    device.isRevoked = true;
    device.isTrusted = false;
    await deviceRepo.save(device);

    await ActivityService.log(Event.DEVICE_REVOKED, {
      userId,
      deviceId,
      ip: device.ipAddress || undefined,
      userAgent: device.userAgent || undefined,
      location: device.location || undefined,
      metadata: {
        deviceType: device.deviceType,
        revokedAt: new Date(),
      },
    });

    return device;
  }

  static async isDeviceTrusted(
    userId: string,
    deviceId: string
  ): Promise<boolean> {
    const device = await deviceRepo.findOne({
      where: { userId, deviceId, isRevoked: false },
    });

    return device?.isTrusted ?? false;
  }

  static async getTrustedDevices(userId: string) {
    return deviceRepo.find({
      where: { userId, isTrusted: true, isRevoked: false },
      order: { lastActive: 'DESC' },
    });
  }

  private static async checkForSuspiciousDevice(
    userId: string,
    newDevice: Device
  ) {
    const userDevices = await deviceRepo.find({
      where: { userId, isRevoked: false },
      order: { lastActive: 'DESC' },
    });

    // Check if this is from a completely new location
    const knownLocations = userDevices.map((d) => d.location).filter(Boolean);

    const isNewLocation =
      newDevice.location && !knownLocations.includes(newDevice.location);

    // Check if this is a new device type
    const knownDeviceTypes = [...new Set(userDevices.map((d) => d.deviceType))];
    const isNewDeviceType = !knownDeviceTypes.includes(newDevice.deviceType);

    // If new location or device type, flag as suspicious
    if (isNewLocation || (isNewDeviceType && userDevices.length > 0)) {
      await ActivityService.log(Event.SUSPICIOUS_ACTIVITY, {
        userId,
        deviceId: newDevice.deviceId,
        ip: newDevice.ipAddress || undefined,
        userAgent: newDevice.userAgent || undefined,
        location: newDevice.location || undefined,
        metadata: {
          reason: isNewLocation ? 'new_location' : 'new_device_type',
          deviceType: newDevice.deviceType,
          previousLocations: knownLocations,
          previousDeviceTypes: knownDeviceTypes,
        },
      });

      // Send security alert
      await SecurityAlertService.sendNewDeviceAlert(userId, newDevice);
    }
  }

  static async listDevicesForUser(userId: string) {
    return deviceRepo.find({
      where: { userId },
      order: { lastActive: 'DESC' },
    });
  }
}
