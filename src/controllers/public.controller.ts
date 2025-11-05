// src/controllers/public.controller.ts
import { Request, Response } from 'express';
import * as publicService from '../services/public.service';
import logger from '../utils/logger'; // <-- YENİ

/**
 * Tekrarlanan try/catch bloklarını önlemek için
 * bir servis fonksiyonunu çalıştıran genel bir yardımcı
 */
const handleRequest = (
    serviceFunction: (languageCode: string) => Promise<any>
) => async (req: Request, res: Response) => {
    try {
        const languageCode = (req.query.lang as string) || 'tr';
        const data = await serviceFunction(languageCode);

        return res.status(200).json({ status: 'success', data });
    } catch (error: any) {
        logger.error(error, `Public Data Hatası (${serviceFunction.name})`); // <-- DEĞİŞTİ
        throw error; // Global error handler'a yönlendir
    }
};

// Her servis için bir handler oluştur
export const getEquipment = handleRequest(publicService.getEquipmentService);
export const getBodyParts = handleRequest(publicService.getBodyPartsService);
export const getLocations = handleRequest(publicService.getLocationsService);
export const getLimitations = handleRequest(publicService.getLimitationsService);