// Dosya: src/controllers/program.controller.ts
import { Request, Response } from 'express';
import * as programService from '../services/program.service';
import logger from '../utils/logger';
import { ProfileCreationInput } from '../utils/zod.schemas';

/**
 * Kayıt öncesi program önizlemesi oluşturur.
 */
export const generateProgramPreviewHandler = async (
    req: Request<{}, {}, ProfileCreationInput>,
    res: Response,
) => {
    try {
        const languageCode = (req.query.lang as string) || 'tr';

        // Servise Zod'dan gelen tüm profil verisini gönder
        const previewData = await programService.generateProgramPreview(
            req.body,
            languageCode,
        );

        if (!previewData) {
            return res.status(404).json({
                status: 'error',
                code: 'PROGRAM_PREVIEW_NOT_FOUND',
                message: 'Uygun bir program şablonu bulunamadı.',
            });
        }

        return res.status(200).json({
            status: 'success',
            data: previewData,
        });
    } catch (error: any) {
        logger.error(error, 'Generate Program Preview Handler Error');
        throw error;
    }
};

/**
 * Herkesin görebileceği program şablonlarını listeler.
 */
export const getTemplateProgramsHandler = async (req: Request, res: Response) => {
    try {
        const languageCode = (req.query.lang as string) || 'tr';

        const programs = await programService.getTemplatePrograms(languageCode);

        return res.status(200).json({
            status: 'success',
            data: programs,
        });
    } catch (error: any) {
        logger.error(error, 'Get Template Programs Handler Error');
        throw error;
    }
};