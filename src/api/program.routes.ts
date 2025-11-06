// Dosya: src/api/program.routes.ts
import { Router } from 'express';
import {
    generateProgramPreviewHandler,
    getTemplateProgramsHandler,
} from '../controllers/program.controller';
import { publicApiLimiter } from '../middlewares/rateLimiter';
import { validate } from '../middlewares/validate';
import { profileDataSchema } from '../utils/zod.schemas';

const router = Router();

/**
 * @route POST /api/v1/programs/generate-preview
 * @desc Kayıt öncesi, kullanıcının profil verilerine göre
 * "Stateless" (veritabanına kaydetmeden) bir program önerisi oluşturur.
 * @access Public (Rate Limitli)
 */
router.post(
    '/generate-preview',
    publicApiLimiter,
    validate(z.object({ body: profileDataSchema })), // Zod şemasının 'body' kısmını doğrula
    generateProgramPreviewHandler,
);

/**
 * @route GET /api/v1/programs/templates
 * @desc Tüm "Genel Şablon" (premium olmayan) programları listeler.
 * @access Public (Rate Limitli)
 */
router.get(
    '/templates',
    publicApiLimiter,
    getTemplateProgramsHandler,
);

// TODO: Gelecekte 'GET /programs/:id' (program detayları) eklenecek

export default router;