export interface IDeviceDTO {
  userId: string;
  deviceId?: string; // optional when creating (server may generate)
  ip?: string;
  userAgent?: string;
  location?: string;
  isTrusted?: boolean;
}
