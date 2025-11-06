// Dosya: src/controllers/schedule.controller.ts
import { Request, Response } from 'express';
import { getMyScheduleService, updateMyScheduleService } from '../services/schedule.service';
import logger from '../utils/logger';
import { UpdateScheduleInput } from '../utils/zod.schemas';

/**
 * Giriş yapmış kullanıcının takvimini getirir.
 */
export const getMyScheduleHandler = async (req: Request, res: Response) => {
    try {
        const userId = req.user!.sub; // checkJwt'den geldiği garanti

        const schedule = await getMyScheduleService(userId);

        return res.status(200).json({
            status: 'success',
            data: schedule,
        });
    } catch (error: any) {
        logger.error(error, 'Get My Schedule Handler Error');
        throw error;
    }
};

/**
 * Giriş yapmış kullanıcının takvimini günceller.
 */
export const updateMyScheduleHandler = async (
    req: Request<{}, {}, UpdateScheduleInput['body']>,
    res: Response,
) => {
    try {
        const userId = req.user!.sub; // checkJwt'den geldiği garanti
        const { assignments } = req.body;

        await updateMyScheduleService(userId, assignments);

        return res.status(200).json({
            status: 'success',
            message: 'Schedule updated successfully.',
        });
    } catch (error: any) {
        logger.error(error, 'Update My Schedule Handler Error');
        // Spesifik hataları yakalayabiliriz, örn: Program ID bulunamadı
        if (error.code === 'P2003') { // Foreign key constraint failed
            logger.warn(error, 'Update Schedule Failed: Program ID not found');
            return res.status(400).json({
                status: 'error',
                code: 'SCHEDULE_INVALID_PROGRAM_ID',
                message: 'One of the provided program IDs does not exist.'
            });
        }
        throw error;
    }
};