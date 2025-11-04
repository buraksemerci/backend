import { Router } from 'express';
import { checkJwt } from '../middlewares/auth';
import {
    registerUserHandler,
    loginUserHandler,
    verifyCodeHandler,
    resendCodeHandler,
    forgotPasswordHandler,
    resetPasswordHandler,
    socialRegisterHandler,
    socialLoginHandler,
    socialMergeHandler,
    refreshTokenHandler,
    logoutUserHandler
} from '../controllers/auth.controller';
import { validate } from '../middlewares/validate'; // Sizin yeni middleware'iniz
import {
    registerSchema,
    loginSchema,
    verifyCodeSchema,
    forgotPasswordSchema,
    resetPasswordSchema,
    socialRegisterSchema,
    socialLoginSchema,
    socialMergeSchema,
    refreshSchema,
    logoutSchema
} from '../utils/zod.schemas';

const router = Router();

router.post(
    '/register',
    validate(registerSchema), // <-- Değişti
    registerUserHandler
);

// === YENİ LOGIN ENDPOINT'İ ===
/**
 * @route POST /api/v1/auth/login
 * @desc Kullanıcı girişi (email VEYA username ile)
 * @access Public
 */
router.post(
    '/login',
    validate(loginSchema), // 1. Zod ile isteği doğrula
    loginUserHandler         // 2. Doğrulanmışsa, controller'a gönder
);
// === Token GEREKTİREN Rotalar ===

/**
 * @route POST /api/v1/auth/verify-code
 * @desc E-posta doğrulama kodunu doğrular
 * @access Private ("Doğrulanmamış" Token Gerekli)
 */
router.post(
    '/verify-code',
    checkJwt, // 1. Kullanıcının bir token'ı var mı? (Giriş yapmış mı?)
    validate(verifyCodeSchema), // 2. Zod ile 6 haneli kodu doğrula
    verifyCodeHandler // 3. Controller'a gönder
);

/**
 * @route POST /api/v1/auth/resend-code
 * @desc Yeni bir e-posta doğrulama kodu gönderir
 * @access Private ("Doğrulanmamış" Token Gerekli)
 */
router.post(
    '/resend-code',
    checkJwt, // 1. Kullanıcının bir token'ı var mı? (Giriş yapmış mı?)
    resendCodeHandler // 2. Controller'a gönder
);

/**
 * @route POST /api/v1/auth/forgot-password
 * @desc Şifre sıfırlama kodu ister (Güvenli Akış)
 * @access Public
 */
router.post(
    '/forgot-password',
    validate(forgotPasswordSchema), // 1. Zod ile e-postayı doğrula
    forgotPasswordHandler          // 2. Controller'a gönder
);


/**
 * @route POST /api/v1/auth/reset-password
 * @desc Şifreyi, geçerli bir kod ile sıfırlar
 * @access Public
 */
router.post(
    '/reset-password',
    validate(resetPasswordSchema), // 1. Zod ile (email, code, newPassword) doğrula
    resetPasswordHandler           // 2. Controller'a gönder
);
/**
 * @route POST /api/v1/auth/social/register
 * @desc Sosyal sağlayıcı (Google vb.) ile yeni kullanıcı kaydı
 * @access Public
 */
router.post(
    '/social/register',
    validate(socialRegisterSchema), // 1. Zod ile isteği doğrula
    socialRegisterHandler          // 2. Controller'a gönder
);
/**
 * @route POST /api/v1/auth/social/login
 * @desc Sosyal sağlayıcı (Google vb.) ile giriş yapar
 * @access Public
 */
router.post(
    '/social/login',
    validate(socialLoginSchema), // 1. Zod ile isteği doğrula
    socialLoginHandler          // 2. Controller'a gönder
);
/**
 * @route POST /api/v1/auth/social/merge
 * @desc Lokal bir hesabı (şifreyle doğrulayarak) sosyal sağlayıcıyla birleştirir
 * @access Public
 */
router.post(
    '/social/merge',
    validate(socialMergeSchema), // 1. Zod ile doğrula
    socialMergeHandler          // 2. Controller'a gönder
);
/**
 * @route POST /api/v1/auth/refresh
 * @desc Refresh token kullanarak yeni bir access token alır
 * @access Public
 */
router.post(
    '/refresh',
    validate(refreshSchema), // 1. Zod ile doğrula
    refreshTokenHandler      // 2. Controller'a gönder
);
/**
 * @route POST /api/v1/auth/logout
 * @desc Kullanıcının oturumunu sonlandırır (Refresh Token'ı siler)
 * @access Private (Access Token Gerekli)
 */
router.post(
    '/logout',
    checkJwt, // 1. Kullanıcının kim olduğunu bilmeliyiz
    validate(logoutSchema), // 2. Zod ile doğrula
    logoutUserHandler // 2. Controller'a gönder
);

export default router;