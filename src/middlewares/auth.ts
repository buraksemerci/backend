import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'varsayilan-cok-gizli-anahtar-degistirin';

// Bu arayazılım, kullanıcının "en azından bir token'a sahip olmasını" zorunlu kılar.
// Token'ın "doğrulanmış" (isEmailVerified) olup olmadığını kontrol ETMEZ.
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
        // Diğer middleware/controller'ların bu bilgiye erişebilmesi için
        // @ts-ignore (Veya Request tipini genişletmemiz gerekir)
        req.user = payload;

        next();
    } catch (error) {
        // Token geçersiz veya süresi dolmuş
        return res.status(401).json({ status: 'error', message: 'Geçersiz veya süresi dolmuş token.' });
    }
};