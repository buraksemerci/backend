// Dosya: src/app.ts
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

// Middlewares
app.use(express.json());
// CORS configuration - allow all origins for development
app.use(cors({
    origin: true, // Allow all origins
    credentials: true, // Allow credentials
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

// --- NEW Logger Middleware ---
app.use(pinoHttp({ logger }));

// Simple health check endpoint
app.get('/health', (req, res) => {
    res.status(200).send('API is healthy and running!');
});

// === MAIN API ROUTING ===
app.use('/api/v1', apiRouter);

// --- NEW GLOBAL ERROR HANDLER ---
// (Express 5 routes async errors here automatically)
app.use((error: Error, req: Request, res: Response, next: NextFunction) => {
    logger.error(error, `Request ${req.method} ${req.path} failed`);

    // 1. Catch Zod (Validation) Errors
    if (error instanceof ZodError) {
        return res.status(400).json({
            status: 'error',
            code: 'VALIDATION_FAILED',
            errors: error.issues.map((issue) => ({
                path: issue.path.join('.'),
                code: issue.code, // Send the Zod error code (e.g., "too_small")
            })),
        });
    }

    // 2. Catch Prisma (Database) Errors
    if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
            return res.status(409).json({
                status: 'error',
                code: 'DB_UNIQUE_CONSTRAINT_FAILED',
                // Optionally send which fields caused the conflict
                meta: {
                    target: (error.meta as any)?.target,
                },
            });
        }
        return res.status(500).json({
            status: 'error',
            code: 'DB_ERROR',
            message: `Prisma error code: ${error.code}`,
        });
    }

    // 3. All other unexpected errors
    return res.status(500).json({
        status: 'error',
        code: 'INTERNAL_SERVER_ERROR',
        message: 'An unexpected server error occurred.',
    });
});

export default app;