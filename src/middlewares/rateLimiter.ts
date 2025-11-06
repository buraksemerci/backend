// Dosya: src/middlewares/rateLimiter.ts
import { rateLimit } from 'express-rate-limit';

/**
 * Prevents brute-force or spam requests to public endpoints (Equipment list, etc.)
 * Rule: 1000 requests per 15 minutes per IP.
 */
export const publicApiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1000, // 1000 requests per IP per 15 min
    message: {
        status: 'error',
        code: 'COMMON_TOO_MANY_REQUESTS',
    },
    standardHeaders: true, // Add "RateLimit-*" headers to response
    legacyHeaders: false, // Disable "X-RateLimit-*" headers
    statusCode: 429, // Explicitly set status code for rate limit exceeded
    skip: (req) => {
        // Skip rate limiting for OPTIONS requests (CORS preflight)
        if (req.method === 'OPTIONS') {
            return true;
        }
        return false;
    },
});
/**
 * Prevents brute-force and spam against auth endpoints (login, register, forgot-password).
 * Rule: 20 requests per 15 minutes per IP (stricter).
 */
export const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // 20 attempts per IP per 15 min
    message: {
        status: 'error',
        code: 'AUTH_TOO_MANY_REQUESTS',
    },
    standardHeaders: true,
    legacyHeaders: false,
    statusCode: 429, // Explicitly set status code for rate limit exceeded
    skip: (req) => {
        // Skip rate limiting for OPTIONS requests (CORS preflight)
        if (req.method === 'OPTIONS') {
            return true;
        }
        return false;
    },
});