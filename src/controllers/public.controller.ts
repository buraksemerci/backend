// Dosya: src/controllers/public.controller.ts

import { Request, Response } from 'express';
import * as publicService from '../services/public.service';

/**
 * Tekrarlanan try/catch bloklarını önlemek için
 * bir servis fonksiyonunu çalıştıran genel bir yardımcı (GÜNCELLENDİ)
 */
const handleRequest = (
    // Servis fonksiyonu artık (languageCode: string) alıyor
    serviceFunction: (languageCode: string) => Promise<any>
) => async (req: Request, res: Response) => {
    try {
        // 1. Dili query string'den al (örn: /public/equipment?lang=tr)
        // Eğer dil gelmezse varsayılan olarak 'tr' kullan.
        const languageCode = (req.query.lang as string) || 'tr';

        // 2. Dili servise ilet
        const data = await serviceFunction(languageCode);

        return res.status(200).json({ status: 'success', data });
    } catch (error: any) {
        console.error(`Public Data Hatası (${serviceFunction.name}):`, error);
        return res.status(500).json({
            status: 'error',
            message: 'Sunucu hatası: Veriler alınamadı.',
        });
    }
};

// Her servis için bir handler oluştur (Bu kısım aynı kalır)
export const getEquipment = handleRequest(publicService.getEquipmentService);
export const getBodyParts = handleRequest(publicService.getBodyPartsService);
export const getLocations = handleRequest(publicService.getLocationsService);
export const getLimitations = handleRequest(publicService.getLimitationsService);