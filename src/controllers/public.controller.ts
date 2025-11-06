// Dosya: src/controllers/public.controller.ts
import { Request, Response } from 'express';
import * as publicService from '../services/public.service';
import logger from '../utils/logger';
import { GENDER_IDS } from '../utils/constants'; // GENDER ID sabitlerimizi import et

/**
 * GÜNCELLENDİ: Servis fonksiyonuna (languageCode) ve (genderId) geçiren 
 * genel bir yardımcı.
 */
const handleRequest = (
    serviceFunction: (
        languageCode: string,
        genderId?: number | null, // Artık cinsiyet ID'si alabilir
    ) => Promise<any>,
) => async (req: Request, res: Response) => {
    try {
        const languageCode = (req.query.lang as string) || 'tr';

        // YENİ: Gelen 'gender' query string'ini ('male', 'female') ID'ye çevir
        const genderKey = (req.query.gender as string)?.toUpperCase();
        let genderId: number | null = null;

        if (genderKey === 'MALE') {
            genderId = GENDER_IDS.MALE;
        } else if (genderKey === 'FEMALE') {
            genderId = GENDER_IDS.FEMALE;
        } else if (genderKey === 'UNKNOWN' || genderKey === 'OTHER') {
            genderId = GENDER_IDS.UNKNOWN;
        }

        // Servis fonksiyonunu hem dil hem de cinsiyet ID'si ile çağır
        const data = await serviceFunction(languageCode, genderId);

        return res.status(200).json({ status: 'success', data });
    } catch (error: any) {
        logger.error(error, `Public Data Error (${serviceFunction.name})`);
        throw error; // Global error handler'a ilet
    }
};

// --- Mevcut Endpoint'ler (handleRequest'i kullandıkları için otomatik güncellendiler) ---
export const getEquipment = handleRequest(publicService.getEquipmentService);
export const getBodyPart = handleRequest(publicService.getBodyPartService);
export const getLocation = handleRequest(publicService.getLocationService);
export const getLimitation = handleRequest(publicService.getLimitationService);

// --- YENİ Endpoint'ler (Normalleştirilmiş Ana Veri için) ---
export const getActivityLevel = handleRequest(
    publicService.getActivityLevelService,
);
export const getBodyType = handleRequest(
    publicService.getBodyTypeService,
);
export const getFitnessLevel = handleRequest(
    publicService.getFitnessLevelService,
);
export const getGoalType = handleRequest(
    publicService.getGoalTypeService,
);
export const getGender = handleRequest(
    publicService.getGenderService,
);
// ... (İhtiyaç duyulan diğer ana veri endpoint'leri buraya eklenebilir)