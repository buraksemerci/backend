// src/controllers/auth.controller.ts
import { Request, Response } from 'express';
import {
    RegisterInput,
    LoginInput,
    VerifyCodeInput,
    ForgotPasswordInput,
    ResetPasswordInput,
    SocialRegisterInput,
    SocialLoginInput,
    SocialMergeInput,
    RefreshInput,
    LogoutInput
} from '../utils/zod.schemas';
import {
    registerUserService,
    loginUserService,
    verifyEmailCodeService,
    resendVerificationCodeService,
    forgotPasswordService,
    resetPasswordService,
    socialRegisterService,
    socialLoginService,
    socialMergeService,
    refreshTokenService,
    logoutUserService
} from '../services/auth.service';
import logger from '../utils/logger'; // <-- YENİ

// === REGISTER HANDLER ===
export const registerUserHandler = async (
    req: Request<{}, {}, RegisterInput['body']>,
    res: Response
) => {
    try {
        const ipAddress = req.ip || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';

        const tokens = await registerUserService(req.body, ipAddress, userAgent, req.body.deviceId);

        return res.status(201).json({
            status: 'success',
            message: 'Kayıt başarılı. Lütfen e-postanızı doğrulayın.',
            data: tokens,
        });
    } catch (error: any) {
        if (error.message === 'CONFLICT') {
            return res.status(409).json({
                status: 'error',
                message: 'Bu e-posta adresi veya kullanıcı adı zaten kullanımda.',
            });
        }
        logger.error(error, 'Register Handler Hatası'); // <-- DEĞİŞTİ
        // Global error handler'a gitmesi için hatayı fırlat
        throw error;
    }
};

// === LOGIN HANDLER ===
export const loginUserHandler = async (
    req: Request<{}, {}, LoginInput['body']>,
    res: Response
) => {
    try {
        const ipAddress = req.ip || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';

        const tokens = await loginUserService(req.body, ipAddress, userAgent, req.body.deviceId);

        return res.status(200).json({
            status: 'success',
            message: 'Giriş başarılı.',
            data: tokens,
        });
    } catch (error: any) {
        if (error.message === 'INVALID_CREDENTIALS') {
            return res.status(401).json({
                status: 'error',
                message: 'Geçersiz e-posta/kullanıcı adı veya şifre.',
            });
        }
        logger.error(error, 'Login Handler Hatası'); // <-- DEĞİŞTİ
        throw error;
    }
};

// === VERIFY CODE HANDLER ===
export const verifyCodeHandler = async (
    req: Request<{}, {}, VerifyCodeInput['body']>,
    res: Response
) => {
    try {
        if (!req.user) {
            return res.status(403).json({ status: 'error', message: 'Yetkisiz erişim.' });
        }
        const userId = req.user.sub;
        const { code, deviceId } = req.body;
        const ipAddress = req.ip || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';

        const tokens = await verifyEmailCodeService(userId, code, ipAddress, userAgent, deviceId);

        return res.status(200).json({
            status: 'success',
            message: 'E-posta başarıyla doğrulandı.',
            data: tokens,
        });
    } catch (error: any) {
        if (error.message === 'INVALID_CODE') {
            return res.status(400).json({
                status: 'error',
                message: 'Geçersiz veya süresi dolmuş doğrulama kodu.',
            });
        }
        if (error.message === 'ALREADY_VERIFIED') {
            return res.status(400).json({
                status: 'error',
                message: 'Bu hesap zaten doğrulanmış.',
            });
        }
        logger.error(error, 'Verify Code Handler Hatası'); // <-- DEĞİŞTİ
        throw error;
    }
};

// === RESEND CODE HANDLER ===
export const resendCodeHandler = async (req: Request, res: Response) => {
    try {
        if (!req.user) {
            return res.status(403).json({ status: 'error', message: 'Yetkisiz erişim.' });
        }
        const userId = req.user.sub;
        const ipAddress = req.ip || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';

        await resendVerificationCodeService(userId, ipAddress, userAgent);

        return res.status(200).json({
            status: 'success',
            message: 'Yeni doğrulama kodu başarıyla gönderildi.',
        });
    } catch (error: any) {
        if (error.message === 'ALREADY_VERIFIED') {
            return res.status(400).json({
                status: 'error',
                message: 'Bu hesap zaten doğrulanmış.',
            });
        }
        logger.error(error, 'Resend Code Handler Hatası'); // <-- DEĞİŞTİ
        throw error;
    }
};

// === FORGOT PASSWORD HANDLER ===
export const forgotPasswordHandler = async (
    req: Request<{}, {}, ForgotPasswordInput['body']>,
    res: Response
) => {
    try {
        const { email } = req.body;
        const ipAddress = req.ip || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';

        await forgotPasswordService(email, ipAddress, userAgent);

        return res.status(200).json({
            status: 'success',
            message: 'İsteğiniz alındı. Eğer bu e-posta adresi kayıtlı ve doğrulanmış ise, bir şifre sıfırlama kodu gönderilecektir.',
        });
    } catch (error: any) {
        logger.error(error, 'Forgot Password Handler Hatası'); // <-- DEĞİŞTİ
        throw error;
    }
};

// === RESET PASSWORD HANDLER ===
export const resetPasswordHandler = async (
    req: Request<{}, {}, ResetPasswordInput['body']>,
    res: Response
) => {
    try {
        await resetPasswordService(req.body);

        return res.status(200).json({
            status: 'success',
            message: 'Şifreniz başarıyla sıfırlandı. Şimdi giriş yapabilirsiniz.',
        });
    } catch (error: any) {
        if (error.message === 'INVALID_CODE') {
            return res.status(400).json({
                status: 'error',
                message: 'Geçersiz, süresi dolmuş veya daha önce kullanılmış bir kod girdiniz.',
            });
        }
        if (error.message === 'NO_LOCAL_ACCOUNT') {
            return res.status(400).json({
                status: 'error',
                message: 'Bu hesap, şifre sıfırlamayı desteklemeyen bir sosyal giriş yöntemi (Google, Apple vb.) ile oluşturulmuş.',
            });
        }
        logger.error(error, 'Reset Password Handler Hatası'); // <-- DEĞİŞTİ
        throw error;
    }
};

// === SOCIAL REGISTER HANDLER ===
export const socialRegisterHandler = async (
    req: Request<{}, {}, SocialRegisterInput['body']>,
    res: Response
) => {
    try {
        const ipAddress = req.ip || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';

        const tokens = await socialRegisterService(req.body, ipAddress, userAgent, req.body.deviceId);

        return res.status(201).json({
            status: 'success',
            message: 'Sosyal kayıt başarılı.',
            data: tokens,
        });
    } catch (error: any) {
        if (error.message === 'TOKEN_VERIFICATION_FAILED') {
            return res.status(401).json({
                status: 'error',
                message: 'Geçersiz veya süresi dolmuş sosyal sağlayıcı token\'ı.',
            });
        }
        if (error.message === 'CONFLICT') {
            return res.status(409).json({
                status: 'error',
                message: 'Bu e-posta adresi zaten farklı bir yöntemle doğrulanmış.',
            });
        }
        logger.error(error, 'Social Register Handler Hatası'); // <-- DEĞİŞTİ
        throw error;
    }
};

// === SOCIAL LOGIN HANDLER ===
export const socialLoginHandler = async (
    req: Request<{}, {}, SocialLoginInput['body']>,
    res: Response
) => {
    try {
        const ipAddress = req.ip || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';

        const tokens = await socialLoginService(req.body, ipAddress, userAgent, req.body.deviceId);

        return res.status(200).json({
            status: 'success',
            message: 'Sosyal giriş başarılı.',
            data: tokens,
        });
    } catch (error: any) {
        if (error.message === 'TOKEN_VERIFICATION_FAILED') {
            return res.status(401).json({
                status: 'error',
                message: 'Geçersiz veya süresi dolmuş sosyal sağlayıcı token\'ı.',
            });
        }
        if (error.message === 'USER_NOT_FOUND') {
            return res.status(404).json({
                status: 'error',
                message: 'Bu sosyal hesap ile kayıtlı bir kullanıcı bulunamadı.',
            });
        }
        if (error.message === 'ACCOUNT_MERGE_REQUIRED') {
            return res.status(409).json({
                status: 'error',
                message: 'Bu e-posta adresi zaten bir şifre ile kayıtlı. Lütfen şifrenizle giriş yapıp hesapları birleştirin.',
                code: 'ACCOUNT_MERGE_REQUIRED'
            });
        }
        logger.error(error, 'Social Login Handler Hatası'); // <-- DEĞİŞTİ
        throw error;
    }
};

// === YENİ SOCIAL MERGE HANDLER'I ===
export const socialMergeHandler = async (
    req: Request<{}, {}, SocialMergeInput['body']>,
    res: Response
) => {
    try {
        const ipAddress = req.ip || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';

        const tokens = await socialMergeService(req.body, ipAddress, userAgent, req.body.deviceId);

        return res.status(200).json({
            status: 'success',
            message: 'Hesaplar başarıyla birleştirildi.',
            data: tokens,
        });

    } catch (error: any) {
        if (error.message === 'TOKEN_VERIFICATION_FAILED') {
            return res.status(401).json({
                status: 'error',
                message: 'Geçersiz sosyal sağlayıcı token\'ı.',
            });
        }
        if (error.message === 'INVALID_CREDENTIALS') {
            return res.status(401).json({
                status: 'error',
                message: 'E-posta veya şifre hatalı. Birleştirme başarısız.',
            });
        }
        logger.error(error, 'Social Merge Handler Hatası'); // <-- DEĞİŞTİ
        throw error;
    }
};

// === YENİ REFRESH TOKEN HANDLER'I ===
export const refreshTokenHandler = async (
    req: Request<{}, {}, RefreshInput['body']>,
    res: Response
) => {
    try {
        const ipAddress = req.ip || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';

        const tokens = await refreshTokenService(req.body.refreshToken, req.body.deviceId, ipAddress, userAgent); // <-- Sıralama düzeltildi

        return res.status(200).json({
            status: 'success',
            message: 'Token başarıyla yenilendi.',
            data: tokens,
        });

    } catch (error: any) {
        if (error.message === 'INVALID_REFRESH_TOKEN') {
            return res.status(401).json({
                status: 'error',
                message: 'Geçersiz, süresi dolmuş veya kullanılmış refresh token.',
            });
        }
        logger.error(error, 'Refresh Token Handler Hatası'); // <-- DEĞİŞTİ
        throw error;
    }
};

// === LOGOUT HANDLER ===
export const logoutUserHandler = async (req: Request<{}, {}, LogoutInput['body']>, res: Response) => {
    try {
        if (!req.user) {
            return res.status(403).json({ status: 'error', message: 'Yetkisiz erişim.' });
        }
        const userId = req.user.sub;
        const { deviceId } = req.body;

        await logoutUserService(userId, deviceId);

        return res.status(200).json({
            status: 'success',
            message: 'Başarıyla çıkış yapıldı.',
        });

    } catch (error: any) {
        logger.error(error, 'Logout Handler Hatası'); // <-- DEĞİŞTİ
        throw error;
    }
};