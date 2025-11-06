// Dosya: src/app.ts
import dotenv from 'dotenv';
dotenv.config();

import express, { Request, Response, NextFunction } from 'express';
import apiRouter from './api/index';
import logger from './utils/logger';
import pinoHttp from 'pino-http';
import { ZodError } from 'zod';
import { Prisma } from '@prisma/client';

const app = express();

// Manual CORS - FIRST middleware, before everything else
app.use((req, res, next) => {
    // Set CORS headers for all requests
    const origin = req.headers.origin;
    res.header('Access-Control-Allow-Origin', origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Max-Age', '86400');

    // Handle OPTIONS requests (CORS preflight)
    if (req.method === 'OPTIONS') {
        return res.status(204).end();
    }

    next();
});

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Logger Middleware
app.use(pinoHttp({ logger }));

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).send('API is healthy and running!');
});

// === MAIN API ROUTING ===
app.use('/api/v1', apiRouter);

// 404 handler for unmatched routes - MUST be after all routes
app.use((req, res) => {
    logger.warn({ method: req.method, path: req.path }, 'Route not found');
    res.status(404).json({
        status: 'error',
        code: 'ROUTE_NOT_FOUND',
        message: `Route ${req.method} ${req.path} not found`,
    });
});

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