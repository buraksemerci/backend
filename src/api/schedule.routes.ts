// Dosya: src/api/schedule.routes.ts
import { Router } from 'express';
import { checkJwt } from '../middlewares/auth';
import { validate } from '../middlewares/validate';
import { updateScheduleSchema } from '../utils/zod.schemas';
import {
    getMyScheduleHandler,
    updateMyScheduleHandler,
} from '../controllers/schedule.controller';

const router = Router();

// BU ROTALARIN TAMAMI KİMLİK DOĞRULAMASI GEREKTİRİR
router.use(checkJwt);

/**
 * @route GET /api/v1/schedule/me
 * @desc Giriş yapmış kullanıcının 7 günlük takvim atamalarını getirir.
 * @access Private (Geçerli bir Access Token Gerekli)
 */
router.get(
    '/me',
    getMyScheduleHandler,
);

/**
 * @route PUT /api/v1/schedule/me
 * @desc Kullanıcının 7 günlük takvimini topluca günceller.
 * @access Private (Geçerli bir Access Token Gerekli)
 */
router.put(
    '/me',
    validate(updateScheduleSchema), // Yeni Zod şemamızla doğrula
    updateMyScheduleHandler,
);

export default router;