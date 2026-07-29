/**
 * Challanges facing on the auth services : 
 * 1. When loging in for the first time or sing up when we hit send otp firtst time no otp is sent 
 */
import { Router, Response } from 'express';
import { z } from 'zod';
import prisma from '../db/prisma';
import auth, { AuthRequest } from '../middleware/auth';
import validate from '../middleware/validate';
import { otpLimiter, authLimiter } from '../middleware/rateLimiter';
import * as authService from '../services/auth.service';
 
const router = Router();

const sendOtpSchema = z.object({
  email: z.string().email('Invalid email'),
  phone: z.string().regex(/^\+?\d{7,15}$/, 'Invalid phone number'),
});

const verifyOtpSchema = z.object({
  email: z.string().email('Invalid email'),
  code: z.string().length(4, 'Code must be 4 digits'),
  name: z.string().min(1).max(100).optional(),
  rememberMe: z.boolean().optional(),
  role: z.enum(['customer', 'restaurant_owner', 'driver']).optional(),
});

const refreshSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token is required'),
});

const updateProfileSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  email: z.string().email().optional(),
  avatar: z.string().optional(),
  fcmToken: z.string().optional(),
});

router.post('/send-otp', otpLimiter, validate(sendOtpSchema), async (req, res: Response): Promise<void> => {
  try {
    const { email, phone, role } = req.body;
    await authService.createOtpRecord(email, phone, role);
    res.json({ success: true, message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Core Send OTP Database Error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to initialize OTP request. Please try again.',
    });
  }
});

router.post('/verify-otp', authLimiter, validate(verifyOtpSchema), async (req, res: Response): Promise<void> => {
  try {
    const { email, code, name, rememberMe, role } = req.body;
    const result = await authService.verifyOtpCode(email, code, name, rememberMe, role);

    if (!result) {
      res.status(400).json({
        success: false,
        message: 'Invalid or expired OTP. Please request a new one.',
      });
      return;
    }

    res.json({ success: true, data: result });
  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ success: false, message: 'Failed to verify OTP' });
  }
});

router.post('/refresh', validate(refreshSchema), async (req, res: Response): Promise<void> => {
  try {
    const { refreshToken } = req.body;
    const tokens = await authService.refreshAccessToken(refreshToken);

    if (!tokens) {
      res.status(401).json({ success: false, message: 'Invalid or expired refresh token' });
      return;
    }

    res.json({ success: true, data: tokens });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(500).json({ success: false, message: 'Failed to refresh token' });
  }
});

router.get('/profile', auth, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.userId },
      select: {
        id: true,
        phone: true,
        name: true,
        avatar: true,
        email: true,
        role: true,
        fcmToken: true,
        createdAt: true,
      },
    });
    if (!user) {
      res.status(404).json({ success: false, message: 'User not found' });
      return;
    }
    res.json({ success: true, data: user });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ success: false, message: 'Failed to get profile' });
  }
});

router.put('/profile', auth, validate(updateProfileSchema), async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const data: any = {};
    if (req.body.name !== undefined) data.name = req.body.name;
    if (req.body.email !== undefined) data.email = req.body.email;
    if (req.body.avatar !== undefined) data.avatar = req.body.avatar;
    if (req.body.fcmToken !== undefined) data.fcmToken = req.body.fcmToken;

    const user = await prisma.user.update({
      where: { id: req.userId },
      data,
      select: {
        id: true,
        phone: true,
        name: true,
        avatar: true,
        email: true,
        role: true,
        fcmToken: true,
        createdAt: true,
      },
    });

    res.json({ success: true, data: user });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ success: false, message: 'Failed to update profile' });
  }
});

router.post('/logout', auth, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    await prisma.user.update({
      where: { id: req.userId },
      data: { refreshToken: null },
    });
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ success: false, message: 'Failed to logout' });
  }
});

export default router;
