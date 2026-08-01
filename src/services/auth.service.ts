import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { Prisma } from '@prisma/client';
import config from '../config';
import prisma from '../db/prisma';
import { JwtPayload } from '../middleware/auth';
import { sendOtpEmail } from './email.service';
export const generateOtp = (): string => {
  return Math.floor(1000 + Math.random() * 9000).toString();
};

export const hashOtp = async (otp: string): Promise<string> => {
  return bcrypt.hash(otp, 10);
};

const detectRole = (phone: string): { role: 'customer' | 'driver' | 'restaurant_owner'; cleanPhone: string } => {
  if (phone.startsWith('D+255') || phone.startsWith('D07') || phone.startsWith('D06')) {
    return { role: 'driver', cleanPhone: phone.slice(1) };
  }
  if (phone.startsWith('R')) {
    return { role: 'restaurant_owner', cleanPhone: phone.slice(1) };
  }
  return { role: 'customer', cleanPhone: phone };
};

export const createOtpRecord = async (email: string, phone: string, role?: string): Promise<string> => {
  const otp = generateOtp();
  const hashedOtp = await hashOtp(otp);
  const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);

  const cleanEmail = email.trim().toLowerCase();
  const rawPhone = phone.replace(/[\s-]/g, '');
  const detected = detectRole(rawPhone);
  const userRole: 'customer' | 'driver' | 'restaurant_owner' = (role as any) || detected.role;
  const cleanPhone = detected.cleanPhone;

  const existingUser = await prisma.user.findFirst({
    where: {
      OR: [{ email: cleanEmail }, { phone: cleanPhone }],
    },
  });

  if (existingUser) {
    await prisma.user.update({
      where: { id: existingUser.id },
      data: { otpCode: hashedOtp, otpExpiresAt },
    });
  } else {
    try {
      await prisma.user.create({
        data: {
          email: cleanEmail,
          phone: cleanPhone,
          name: '',
          role: userRole,
          otpCode: hashedOtp,
          otpExpiresAt,
        },
      });
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
        const userRetry = await prisma.user.findFirst({
          where: { OR: [{ email: cleanEmail }, { phone: cleanPhone }] },
        });
        if (userRetry) {
          await prisma.user.update({
            where: { id: userRetry.id },
            data: { otpCode: hashedOtp, otpExpiresAt },
          });
        } else {
          throw error;
        }
      } else {
        throw error;
      }
    }
  }

  try {
    await sendOtpEmail(cleanEmail, otp);
    if (config.isDev) console.log(`[DEV] OTP sent to ${cleanEmail}: ${otp}`);
  } catch (emailError) {
    console.error(`[EMAIL ERROR] Failed delivering to ${cleanEmail}:`, emailError);
    // Propagate the error so the API caller receives feedback and can surface it to the user
    throw emailError;
  }

  return otp;
};

export const verifyOtpCode = async (
  email: string,
  code: string,
  name?: string,
  rememberMe?: boolean,
  role?: string,
): Promise<{ user: any; accessToken: string; refreshToken: string } | null> => {
  const cleanEmail = email.trim().toLowerCase();
  const user = await prisma.user.findUnique({ where: { email: cleanEmail } });
  if (!user || !user.otpCode || !user.otpExpiresAt) return null;

  if (new Date() > user.otpExpiresAt) return null;

  const isValid = await bcrypt.compare(code, user.otpCode);
  if (!isValid) return null;

  const updateData: any = { otpCode: null, otpExpiresAt: null };
  if (name) updateData.name = name;
  if (role) updateData.role = role;

  const updatedUser = await prisma.user.update({
    where: { id: user.id },
    data: updateData,
  });

  const tokens = await generateTokens(updatedUser.id, updatedUser.role, rememberMe);

  return {
    user: sanitizeUser(updatedUser),
    ...tokens,
  };
};

export const generateTokens = async (
  userId: string,
  role: string,
  rememberMe?: boolean,
): Promise<{ accessToken: string; refreshToken: string }> => {
  const accessToken = jwt.sign({ userId, role } as JwtPayload, config.jwt.accessSecret, {
    expiresIn: config.jwt.accessExpiresIn as any,
  });

  const refreshToken = jwt.sign({ userId, role } as JwtPayload, config.jwt.refreshSecret, {
    expiresIn: rememberMe ? config.jwt.rememberExpiresIn : (config.jwt.refreshExpiresIn as any),
  });

  await prisma.user.update({
    where: { id: userId },
    data: { refreshToken: await bcrypt.hash(refreshToken, 5) },
  });

  return { accessToken, refreshToken };
};

export const refreshAccessToken = async (
  token: string,
): Promise<{ accessToken: string; refreshToken: string } | null> => {
  try {
    const decoded = jwt.verify(token, config.jwt.refreshSecret) as JwtPayload;
    const user = await prisma.user.findUnique({ where: { id: decoded.userId } });

    if (!user || !user.refreshToken) return null;

    const isValid = await bcrypt.compare(token, user.refreshToken);
    if (!isValid) return null;

    return generateTokens(user.id, user.role);
  } catch {
    return null;
  }
};

export const sanitizeUser = (user: any) => {
  const { otpCode, otpExpiresAt, refreshToken, ...sanitized } = user;
  return sanitized;
};
