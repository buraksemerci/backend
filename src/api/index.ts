// Dosya: src/api/index.ts
import { Router } from 'express';
import authRouter from './auth.routes';
import publicRouter from './public.routes';
import profileRouter from './profile.routes';
// --- YENİ İMPORTLAR ---
import programRouter from './program.routes';
import scheduleRouter from './schedule.routes';

const router = Router();

// Tüm /auth isteklerini auth.routes.ts'e yönlendir
router.use('/auth', authRouter);
// Tüm /public isteklerini public.routes.ts'e yönlendir
router.use('/public', publicRouter);
// Tüm /profile isteklerini profile.routes.ts'e yönlendir
router.use('/profile', profileRouter);

// --- YENİ ROTALAR ---
// Tüm /programs isteklerini program.routes.ts'e yönlendir
router.use('/programs', programRouter);
// Tüm /schedule isteklerini schedule.routes.ts'e yönlendir
router.use('/schedule', scheduleRouter);

export default router;