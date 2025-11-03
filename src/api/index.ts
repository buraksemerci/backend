import { Router } from 'express';
import authRouter from './auth.routes';
import publicRouter from './public.routes'; // <-- YORUM SATIRINI KALDIRDIK
import profileRouter from './profile.routes';

const router = Router();

// Tüm /auth isteklerini auth.routes.ts'e yönlendir
router.use('/auth', authRouter);
// Tüm /public isteklerini public.routes.ts'e yönlendir
router.use('/public', publicRouter); // <-- YORUM SATIRINI KALDIRDIK

router.use('/profile', profileRouter);

export default router;
