import { rateLimit } from 'express-rate-limit';

/**
 * Public endpoint'lere (Ekipman listesi vb.) yönelik
 * kaba kuvvet (brute-force) veya spam isteklerini önler.
 * Kural: Her IP, bu endpoint'lere 15 dakikada 1000 istek atabilir.
 */
export const publicApiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 1000, // Her IP için 15 dakikada 1000 istek
    message: {
        status: 'error',
        message: 'Çok fazla istekte bulundunuz. Lütfen 15 dakika sonra tekrar deneyin.',
    },
    standardHeaders: true, // "RateLimit-*" başlıklarını yanıta ekle
    legacyHeaders: false, // "X-RateLimit-*" başlıklarını devre dışı bırak
});
/**
 * Auth endpoint'lerine (login, register, forgot-password) yönelik
 * kaba kuvvet (brute-force) saldırılarını ve spam'i önler.
 * Kural: Her IP, bu endpoint'lere 15 dakikada 20 istek atabilir (daha katı).
 */
export const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 20, // Her IP için 15 dakikada 20 deneme
    message: {
        status: 'error',
        message: 'Çok fazla denemede bulundunuz. Lütfen 15 dakika sonra tekrar deneyin.',
    },
    standardHeaders: true,
    legacyHeaders: false,
});
