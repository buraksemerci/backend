// Dosya: src/utils/env.ts
import { z } from 'zod';

// We define a schema for all our environment variables from the .env file.
const envSchema = z.object({
    // Server
    PORT: z.coerce.number().default(5000),
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),

    // Database
    DATABASE_URL: z.string().min(1, 'DATABASE_URL is required.'),

    // JWT
    JWT_SECRET: z.string().min(1, 'JWT_SECRET is required.'),
    JWT_REFRESH_EXPIRATION_DAYS: z.coerce.number().default(30),

    // Google Auth
    GOOGLE_CLIENT_ID: z.string().min(1, 'GOOGLE_CLIENT_ID is required.'),

    // Email (SMTP)
    EMAIL_HOST: z.string().min(1, 'EMAIL_HOST is required.'),
    EMAIL_PORT: z.coerce.number().default(587),
    EMAIL_USER: z.string().min(1, 'EMAIL_USER is required.'),
    EMAIL_PASS: z.string().min(1, 'EMAIL_PASS is required.'),
    EMAIL_FROM: z.string().min(1, 'EMAIL_FROM is required.'),
});

// Validate process.env against this schema
// We use 'parse' instead of 'safeParse' so that the app FAILS TO START if variables are missing.
export const env = envSchema.parse(process.env);