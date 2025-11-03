import { Request, Response } from 'express';
import * as publicService from '../services/public.service';

/**
 * Tekrarlanan try/catch bloklarını önlemek için
 * bir servis fonksiyonunu çalıştıran genel bir yardımcı (wrapper)
 */
const handleRequest = (
    serviceFunction: () => Promise<any>
) => async (req: Request, res: Response) => {
    try {
        const data = await serviceFunction();
        return res.status(200).json({ status: 'success', data });
    } catch (error: any) {
        console.error(`Public Data Hatası (${serviceFunction.name}):`, error);
        return res.status(500).json({
            status: 'error',
            message: 'Sunucu hatası: Veriler alınamadı.',
        });
    }
};

// Her servis için bir handler oluştur
export const getEquipment = handleRequest(publicService.getEquipmentService);
export const getBodyParts = handleRequest(publicService.getBodyPartsService);
export const getLocations = handleRequest(publicService.getLocationsService);
export const getLimitations = handleRequest(publicService.getLimitationsService);
