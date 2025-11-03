import { Request, Response } from 'express';
import { getMyProfileService } from '../services/profile.service';

/**
 * Giriş yapmış kullanıcının profil verilerini getirir
 */
export const getMyProfileHandler = async (req: Request, res: Response) => {
    try {
        // @ts-ignore
        const userId = req.user.sub; // checkJwt middleware'inden gelir

        if (!userId) {
            return res.status(403).json({ status: 'error', message: 'Geçersiz token payload.' });
        }

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

        console.error('Get My Profile Handler Hatası:', error);
        return res.status(500).json({
            status: 'error',
            message: 'Sunucu hatası.',
        });
    }
};
