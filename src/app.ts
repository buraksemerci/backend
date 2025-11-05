// src/app.ts
import dotenv from 'dotenv';
dotenv.config();

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import apiRouter from './api/index';
import logger from './utils/logger';
import pinoHttp from 'pino-http';
import { ZodError } from 'zod';
import { Prisma } from '@prisma/client';

const app = express();

app.set('trust proxy', 1);

// Middleware'ler
app.use(express.json());
app.use(cors());

// --- YENİ Logger Middleware ---
app.use(pinoHttp({ logger }));

// Basit bir "health check" endpoint'i
app.get('/health', (req, res) => {
    res.status(200).send('API is healthy and running!');
});

// === ANA API YÖNLENDİRMESİ ===
app.use('/api/v1', apiRouter);

// --- YENİ GLOBAL HATA YÖNETİCİSİ (ERROR HANDLER) ---
// (Express 5, async hataları otomatik olarak buraya yönlendirir)
app.use((error: Error, req: Request, res: Response, next: NextFunction) => {
    logger.error(error, `İstek ${req.method} ${req.path} başarısız oldu`);

    // 1. Zod (Validasyon) Hatalarını Yakala
    if (error instanceof ZodError) {
        return res.status(400).json({
            status: 'error',
            message: 'Geçersiz istek verisi.',
            errors: error.issues.map((issue) => ({
                path: issue.path.join('.'),
                message: issue.message,
            })),
        });
    }

    // 2. Prisma (Veritabanı) Hatalarını Yakala
    if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
            return res.status(409).json({
                status: 'error',
                message: 'Veri çakışması (örn: bu email zaten kullanımda).',
                meta: error.meta,
            });
        }
        return res.status(500).json({
            status: 'error',
            message: 'Veritabanı hatası.',
            code: error.code,
        });
    }

    // 3. Diğer tüm beklenmedik hatalar
    return res.status(500).json({
        status: 'error',
        message: 'Sunucuda beklenmedik bir hata oluştu.',
    });
});

export default app;