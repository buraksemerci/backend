// Dosya: src/api/public.routes.ts
import { Router } from 'express';
import {
    getEquipment,
    getBodyPart,  // Kontrolcünüzdeki isimlendirmeyle eşleşiyor
    getLocation,  // Kontrolcünüzdeki isimlendirmeyle eşleşiyor
    getLimitation,// Kontrolcünüzdeki isimlendirmeyle eşleşiyor
    // --- YENİ EKLENEN ROTALAR ---
    getActivityLevel,
    getBodyType,
    getFitnessLevel,
    getGoalType,
    getGender
} from '../controllers/public.controller';
import { publicApiLimiter } from '../middlewares/rateLimiter';

const router = Router();

// Bu rotadaki TÜM endpoint'lere hız sınırlayıcıyı uygula
router.use(publicApiLimiter);

// --- MEVCUT ROTALAR ---
router.get('/equipment', getEquipment);
router.get('/body-parts', getBodyPart); // ('getBodyParts' -> 'getBodyPart')
router.get('/locations', getLocation); // ('getLocations' -> 'getLocation')
router.get('/limitations', getLimitation); // ('getLimitations' -> 'getLimitation')

// --- YENİ ANA VERİ ROTALARI ---
router.get('/activity-levels', getActivityLevel);
router.get('/body-types', getBodyType);
router.get('/fitness-levels', getFitnessLevel);
router.get('/goal-types', getGoalType);
router.get('/genders', getGender); // (Kayıt ekranındaki cinsiyet seçimi için)

export default router;