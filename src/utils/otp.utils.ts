import crypto from 'crypto';
import bcrypt from 'bcrypt';
export const generateOTP = (): string => {
  return crypto.randomInt(100000, 999999).toString();
};

export const verifyOTP = (otp: string, hashedOTP: string): boolean => {
  return bcrypt.compareSync(otp, hashedOTP);
};
