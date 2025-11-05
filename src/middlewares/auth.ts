// src/middlewares/auth.ts
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { env } from '../utils/env'; // <-- YENİ

const JWT_SECRET = env.JWT_SECRET; // <-- DEĞİŞTİ

// Bu arayazılım, kullanıcının "en azından bir token'a sahip olmasını" zorunlu kılar.
export const checkJwt = (req: Request, res: Response, next: NextFunction) => {
    // 1. Token'ı Header'dan al (Bearer Token)
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ status: 'error', message: 'Erişim reddedildi. Token bulunamadı.' });
    }

    const token = authHeader.split(' ')[1];

    try {
        // 2. Token'ı doğrula
        const payload = jwt.verify(token, JWT_SECRET) as { sub: string, isEmailVerified: boolean };

        // 3. Payload'ı 'req' nesnesine ekle
        // 'src/types/express/index.d.ts' sayesinde artık tip-güvenli!
        req.user = payload; // <-- @ts-ignore KALDIRILDI

        next();
    } catch (error) {
        // Token geçersiz veya süresi dolmuş
        return res.status(401).json({ status: 'error', message: 'Geçersiz veya süresi dolmuş token.' });
    }
};