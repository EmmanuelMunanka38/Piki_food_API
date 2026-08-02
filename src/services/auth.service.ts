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

export const normalizeEmail = (email: string): string => email.trim().toLowerCase();

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

  const cleanEmail = normalizeEmail(email);
  const rawPhone = phone.replace(/[\s-]/g, '');
  const detected = detectRole(rawPhone);
  const userRole: 'customer' | 'driver' | 'restaurant_owner' = (role as any) || detected.role;
  const cleanPhone = detected.cleanPhone;

  // Verification always looks the user up by email, so the OTP must be stored
  // on a record that is findable by the email used at verify time.
  let user = await prisma.user.findUnique({ where: { email: cleanEmail } });

  if (user) {
    await prisma.user.update({
      where: { id: user.id },
      data: { otpCode: hashedOtp, otpExpiresAt },
    });
    console.log(`[OTP CREATE] Existing email ${cleanEmail} -> refresh OTP on user ${user.id}`);
  } else {
    const phoneOwner = cleanPhone ? await prisma.user.findUnique({ where: { phone: cleanPhone } }) : null;

    if (phoneOwner && phoneOwner.email === null) {
      // Phone-only account: attach the email so email-based verification works.
      user = await prisma.user.update({
        where: { id: phoneOwner.id },
        data: { email: cleanEmail, otpCode: hashedOtp, otpExpiresAt },
      });
      console.log(`[OTP CREATE] Phone-only user ${user.id} -> attach email ${cleanEmail} and store OTP`);
    } else {
      try {
        user = await prisma.user.create({
          data: {
            email: cleanEmail,
            // Only claim the phone if it isn't already used by another account.
            phone: phoneOwner ? null : cleanPhone,
            name: '',
            role: userRole,
            otpCode: hashedOtp,
            otpExpiresAt,
          },
        });
        console.log(`[OTP CREATE] Created user ${user.id} (email=${cleanEmail}, phone=${user.phone}) with OTP`);
      } catch (error) {
        if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
          // Race condition: another request created this email/phone between our
          // lookup and create. Resolve by email (the verification key) and refresh.
          user = await prisma.user.findUnique({ where: { email: cleanEmail } });
          if (!user) throw error;
          await prisma.user.update({
            where: { id: user.id },
            data: { otpCode: hashedOtp, otpExpiresAt },
          });
          console.log(`[OTP CREATE] Race recovered -> refreshed OTP on user ${user.id}`);
        } else {
          throw error;
        }
      }
    }
  }

  try {
    await sendOtpEmail(cleanEmail, otp);
    if (config.isDev) console.log(`[DEV] OTP sent to ${cleanEmail}: ${otp}`);
  } catch (emailError) {
    console.error(`[EMAIL ERROR] Failed delivering to ${cleanEmail}:`, emailError);
    // The OTP record is already committed; surface the failure to the caller.
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
  const cleanEmail = normalizeEmail(email);
  const cleanCode = String(code).trim();

  const user = await prisma.user.findUnique({ where: { email: cleanEmail } });
  if (!user) {
    console.warn(`[OTP VERIFY] No user found for email: ${cleanEmail}`);
    return null;
  }
  if (!user.otpCode || !user.otpExpiresAt) {
    console.warn(`[OTP VERIFY] No OTP in store for user: ${user.id}`);
    return null;
  }
  if (new Date() > user.otpExpiresAt) {
    console.warn(`[OTP VERIFY] OTP expired for user: ${user.id} (expired ${user.otpExpiresAt.toISOString()})`);
    return null;
  }

  const isValid = await bcrypt.compare(cleanCode, user.otpCode);
  if (!isValid) {
    console.warn(`[OTP VERIFY] Invalid OTP code for user: ${user.id}`);
    return null;
  }

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
