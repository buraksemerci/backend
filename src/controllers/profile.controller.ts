// Dosya: src/controllers/profile.controller.ts
import { Request, Response } from 'express';
import { getMyProfileService } from '../services/profile.service';
import logger from '../utils/logger';

/**
 * Fetches the profile data for the logged-in user
 */
export const getMyProfileHandler = async (req: Request, res: Response) => {
    try {
        if (!req.user) {
            return res.status(403).json({ status: 'error', code: 'AUTH_UNAUTHORIZED' });
        }
        const userId = req.user.sub; // Comes from checkJwt middleware

        const profileData = await getMyProfileService(userId);

        return res.status(200).json({
            status: 'success',
            data: profileData,
        });

    } catch (error: any) {
        if (error.message === 'USER_NOT_FOUND') {
            return res.status(404).json({
                status: 'error',
                code: 'PROFILE_USER_NOT_FOUND',
            });
        }

        logger.error(error, 'Get My Profile Handler Error');
        throw error;
    }
};