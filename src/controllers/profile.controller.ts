// src/controllers/profile.controller.ts
import { Request, Response } from 'express';
import { getMyProfileService } from '../services/profile.service';
import logger from '../utils/logger'; // <-- YENİ

/**
 * Giriş yapmış kullanıcının profil verilerini getirir
 */
export const getMyProfileHandler = async (req: Request, res: Response) => {
    try {
        // --- DEĞİŞİKLİK ---
        if (!req.user) {
            return res.status(403).json({ status: 'error', message: 'Yetkisiz erişim.' });
        }
        const userId = req.user.sub; // checkJwt middleware'inden gelir
        // --- DEĞİŞİKLİK SONU ---

        const profileData = await getMyProfileService(userId);

        return res.status(200).json({
            status: 'success',
            data: profileData,
        });

    } catch (error: any) {
        if (error.message === 'USER_NOT_FOUND') {
            return res.status(404).json({
                status: 'error',
                message: 'Kullanıcı bulunamadı.',
            });
        }

        logger.error(error, 'Get My Profile Handler Hatası'); // <-- DEĞİŞTİ
        throw error;
    }
};