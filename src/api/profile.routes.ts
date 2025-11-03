import { Router } from 'express';
import { checkJwt } from '../middlewares/auth';
import { getMyProfileHandler } from '../controllers/profile.controller';

const router = Router();

/**
 * @route GET /api/v1/profile/me
 * @desc Giriş yapmış kullanıcının tüm profil verilerini getirir
 * @access Private (Geçerli bir Access Token Gerekli)
 */
router.get(
    '/me',
    checkJwt, // 1. Kullanıcı giriş yapmış mı?
    getMyProfileHandler // 2. Profili getir
);

// TODO: Gelecekte 'PUT /profile/me' (güncelleme) buraya eklenecek

export default router;
