// src/utils/env.ts
import { z } from 'zod';

// .env dosyamızdaki tüm değişkenler için bir şema tanımlıyoruz.
const envSchema = z.object({
    // Sunucu
    PORT: z.coerce.number().default(5000),
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),

    // Veritabanı
    DATABASE_URL: z.string().min(1, 'DATABASE_URL zorunludur.'),

    // JWT
    JWT_SECRET: z.string().min(1, 'JWT_SECRET zorunludur.'),
    JWT_REFRESH_EXPIRATION_DAYS: z.coerce.number().default(30),

    // Google Auth
    GOOGLE_CLIENT_ID: z.string().min(1, 'GOOGLE_CLIENT_ID zorunludur.'),

    // Email (SMTP)
    EMAIL_HOST: z.string().min(1, 'EMAIL_HOST zorunludur.'),
    EMAIL_PORT: z.coerce.number().default(587),
    EMAIL_USER: z.string().min(1, 'EMAIL_USER zorunludur.'),
    EMAIL_PASS: z.string().min(1, 'EMAIL_PASS zorunludur.'),
    EMAIL_FROM: z.string().min(1, 'EMAIL_FROM zorunludur.'),
});

// process.env'yi bu şemaya göre doğrula
// 'safeParse' yerine 'parse' kullanıyoruz ki eksik değişken varsa uygulama BAŞLAMASIN.
export const env = envSchema.parse(process.env);