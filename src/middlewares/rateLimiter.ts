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

// TODO: Gelecekte 'login' gibi daha hassas endpoint'ler için
// daha katı bir 'authLimiter' da buraya eklenebilir.
