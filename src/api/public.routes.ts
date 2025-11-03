import { Router } from 'express';
import {
    getEquipment,
    getBodyParts,
    getLocations,
    getLimitations,
} from '../controllers/public.controller';
import { publicApiLimiter } from '../middlewares/rateLimiter';

const router = Router();

// Bu rotadaki TÜM endpoint'lere hız sınırlayıcıyı uygula
router.use(publicApiLimiter);

/**
 * @route GET /api/v1/public/equipment
 * @desc Tüm antrenman ekipmanlarının listesini döner
 * @access Public
 */
router.get('/equipment', getEquipment);

/**
 * @route GET /api/v1/public/body-parts
 * @desc Tüm hedeflenebilir vücut bölgelerinin listesini döner
 * @access Public
 */
router.get('/body-parts', getBodyParts);

/**
 * @route GET /api/v1/public/locations
 * @desc Tüm antrenman konumlarının listesini döner
 * @access Public
 */
router.get('/locations', getLocations);

/**
 * @route GET /api/v1/public/limitations
 * @desc Tüm sağlık kısıtlamalarının listesini döner
 * @access Public
 */
router.get('/limitations', getLimitations);

export default router;
