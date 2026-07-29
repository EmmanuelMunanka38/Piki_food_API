//? I dont no why the above commeted implementation was making it very challanging for rate rimiting ?


/* 
I dont real get why this was a challange please read the docs if need to make changes on this file
or contact Emmanuel here:  emmmanuelmunanka38@gmail.com for guidance before implementing or changing this file 
*/ 



/*
import rateLimit from 'express-rate-limit';
import { Request } from 'express';

const emailKeyGenerator = (req: Request): string => {
  return req.body?.email || req.ip || 'unknown';
};

export const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip || 'unknown',
  message: { success: false, message: 'Too many requests, please try again later.' },
});

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: emailKeyGenerator,
  message: { success: false, message: 'Too many auth attempts, please try again later.' },
});

export const otpLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: emailKeyGenerator,
  message: { success: false, message: 'Too many OTP requests. Please wait before trying again.' },
});*/


import rateLimit from 'express-rate-limit';
import { Request } from 'express';

/**
 * Generates a unique key based on normalized email, falling back to IP.
 * Isolates buckets so one user missing an email doesn't block everyone else.
 */
const emailKeyGenerator = (req: Request): string => {
  const clientIp = req.ip || 'unknown-ip';
  const rawEmail = req.body?.email;

  if (typeof rawEmail === 'string' && rawEmail.trim().length > 0) {
    const normalizedEmail = rawEmail.trim().toLowerCase();
    return `email_${normalizedEmail}`;
  }

  return `ip_${clientIp}`;
};

// Base configuration shared across limiters
const baseConfig = {
  standardHeaders: true,
  legacyHeaders: false,
  // Skip CORS preflight requests so mobile apps aren't double-counted
  skip: (req: Request) => req.method === 'OPTIONS',
};

export const generalLimiter = rateLimit({
  ...baseConfig,
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  keyGenerator: (req) => req.ip || 'unknown-ip',
  message: { success: false, message: 'Too many requests, please try again later.' },
});

export const authLimiter = rateLimit({
  ...baseConfig,
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  keyGenerator: emailKeyGenerator,
  message: { success: false, message: 'Too many auth attempts, please try again later.' },
});

export const otpLimiter = rateLimit({
  ...baseConfig,
  windowMs: 60 * 1000, // 1 minute
  max: 3,
  keyGenerator: emailKeyGenerator,
  message: { success: false, message: 'Too many OTP requests. Please wait before trying again.' },
});


