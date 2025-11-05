// Dosya: src/middlewares/auth.ts
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { env } from '../utils/env';

const JWT_SECRET = env.JWT_SECRET;

// This middleware enforces that the user must have "at least some token".
export const checkJwt = (req: Request, res: Response, next: NextFunction) => {
    // 1. Get token from Header (Bearer Token)
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ status: 'error', code: 'AUTH_NO_TOKEN' });
    }

    const token = authHeader.split(' ')[1];

    try {
        // 2. Verify token
        const payload = jwt.verify(token, JWT_SECRET) as { sub: string, isEmailVerified: boolean };

        // 3. Add payload to 'req' object
        // This is now type-safe thanks to 'src/types/express/index.d.ts'!
        req.user = payload;

        next();
    } catch (error) {
        // Token is invalid or expired
        return res.status(401).json({ status: 'error', code: 'AUTH_INVALID_TOKEN' });
    }
};