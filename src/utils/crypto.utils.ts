import crypto from 'crypto';

// Function to hash a value using SHA-256
export function hashValue(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function compareHashedValue(
  value: string,
  hashedValue: string
): boolean {
  return hashValue(value) === hashedValue;
}

export function generateRandomHexString(length: number): string {
  return crypto.randomBytes(length).toString('hex');
}
