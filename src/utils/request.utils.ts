import { Request } from 'express';
import geoip from 'geoip-lite';

export interface ClientInfo {
  ipAddress?: string;
  userAgent?: string;
  location?: string;
}

export function extractClientInfo(req: Request): ClientInfo {
  // Get IP address (handles proxies and load balancers)
  const ipAddress = getClientIP(req);

  // Get user agent
  const userAgent = req.headers['user-agent'];

  // Get location from IP
  const location = getLocationFromIP(ipAddress);

  return {
    ipAddress,
    userAgent,
    location,
  };
}

function getClientIP(req: Request): string | undefined {
  // Check various headers for real IP (common in proxy/load balancer setups)
  const forwarded = req.headers['x-forwarded-for'];

  if (forwarded) {
    // x-forwarded-for can be a comma-separated list
    const ips =
      typeof forwarded === 'string'
        ? forwarded.split(',').map((ip) => ip.trim())
        : forwarded;
    return ips[0];
  }

  // Fallback to other headers
  const realIP = req.headers['x-real-ip'];
  if (realIP && typeof realIP === 'string') {
    return realIP;
  }

  // Last resort: socket address
  return req.socket.remoteAddress;
}

function getLocationFromIP(ip?: string): string | undefined {
  if (!ip) return undefined;

  try {
    const geo = geoip.lookup(ip);
    if (!geo) return undefined;

    return [geo.city, geo.region, geo.country].filter(Boolean).join(', ');
  } catch (error) {
    console.error('Error looking up IP location:', error);
    return undefined;
  }
}

// Optional: Parse user agent for more details
export function parseUserAgent(userAgent?: string) {
  if (!userAgent) return null;

  const ua = userAgent.toLowerCase();

  // Browser detection
  let browser = 'Unknown';
  if (ua.includes('chrome')) browser = 'Chrome';
  else if (ua.includes('firefox')) browser = 'Firefox';
  else if (ua.includes('safari')) browser = 'Safari';
  else if (ua.includes('edge')) browser = 'Edge';
  else if (ua.includes('opera')) browser = 'Opera';

  // OS detection
  let os = 'Unknown';
  if (ua.includes('windows')) os = 'Windows';
  else if (ua.includes('mac')) os = 'macOS';
  else if (ua.includes('linux')) os = 'Linux';
  else if (ua.includes('android')) os = 'Android';
  else if (ua.includes('ios') || ua.includes('iphone') || ua.includes('ipad'))
    os = 'iOS';

  // Device type
  let deviceType = 'Desktop';
  if (ua.includes('mobile')) deviceType = 'Mobile';
  else if (ua.includes('tablet') || ua.includes('ipad')) deviceType = 'Tablet';

  return { browser, os, deviceType };
}
