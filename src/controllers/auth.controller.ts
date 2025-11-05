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
    refreshTokenService, // <-- YENİ
    logoutUserService
} from '../services/auth.service';

// IP ve User Agent'ı req'den alıp servise iletmek için güncellendi

// === REGISTER HANDLER (GÜNCELLENDİ) ===
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
        console.error('Register Handler Hatası:', error);
        return res.status(500).json({
            status: 'error',
            message: 'Sunucu hatası. Lütfen tekrar deneyin.',
        });
    }
};

// === LOGIN HANDLER (GÜNCELLENDİ) ===
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
        console.error('Login Handler Hatası:', error);
        return res.status(500).json({
            status: 'error',
            message: 'Sunucu hatası. Lütfen tekrar deneyin.',
        });
    }
};

// === VERIFY CODE HANDLER (GÜNCELLENDİ) ===
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
        console.error('Verify Code Handler Hatası:', error);
        return res.status(500).json({
            status: 'error',
            message: 'Sunucu hatası. Lütfen tekrar deneyin.',
        });
    }
};

// === RESEND CODE HANDLER (GÜNCELLENDİ) ===
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
        console.error('Resend Code Handler Hatası:', error);
        return res.status(500).json({
            status: 'error',
            message: 'Sunucu hatası. Lütfen tekrar deneyin.',
        });
    }
};

// === FORGOT PASSWORD HANDLER (GÜNCELLENDİ) ===
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
        console.error('Forgot Password Handler Hatası:', error);
        return res.status(500).json({
            status: 'error',
            message: 'Sunucu hatası. Lütfen tekrar deneyin.',
        });
    }
};

// === RESET PASSWORD HANDLER (DEĞİŞMEDİ) ===
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
        console.error('Reset Password Handler Hatası:', error);
        return res.status(500).json({
            status: 'error',
            message: 'Sunucu hatası. Lütfen tekrar deneyin.',
        });
    }
};

// === SOCIAL REGISTER HANDLER (GÜNCELLENDİ) ===
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
        console.error('Social Register Handler Hatası:', error);
        return res.status(500).json({
            status: 'error',
            message: 'Sunucu hatası. Lütfen tekrar deneyin.',
        });
    }
};

// === SOCIAL LOGIN HANDLER (GÜNCELLENDİ) ===
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
        console.error('Social Login Handler Hatası:', error);
        return res.status(500).json({
            status: 'error',
            message: 'Sunucu hatası. Lütfen tekrar deneyin.',
        });
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

        // Servis, her iki kimliği de doğrulayacak ve token döndürecek
        const tokens = await socialMergeService(req.body, ipAddress, userAgent, req.body.deviceId);

        // Başarılı: Hesaplar birleştirildi ve "doğrulanmış" token'lar döndürüldü
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
            // Şifre yanlıştı VEYA e-posta bulunamadı
            return res.status(401).json({
                status: 'error',
                message: 'E-posta veya şifre hatalı. Birleştirme başarısız.',
            });
        }

        // Beklenmedik bir hata
        console.error('Social Merge Handler Hatası:', error);
        return res.status(500).json({
            status: 'error',
            message: 'Sunucu hatası. Lütfen tekrar deneyin.',
        });
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

        // Servis, eski token'ı doğrulayacak ve yeni bir set döndürecek
        const tokens = await refreshTokenService(req.body.refreshToken, ipAddress, userAgent, req.body.deviceId);

        // Başarılı: Yeni token seti
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

        console.error('Refresh Token Handler Hatası:', error);
        return res.status(500).json({
            status: 'error',
            message: 'Sunucu hatası.',
        });
    }
};

export const logoutUserHandler = async (req: Request<{}, {}, LogoutInput['body']>, res: Response) => {
    try {
        if (!req.user) {
            return res.status(403).json({ status: 'error', message: 'Yetkisiz erişim.' });
        }
        const userId = req.user.sub; // checkJwt'den gelen 'userId'
        const { deviceId } = req.body; // Zod'dan gelen 'deviceId'

        await logoutUserService(userId, deviceId); // <-- DEĞİŞTİ

        // Başarılı: Token'lar silindi
        return res.status(200).json({
            status: 'success',
            message: 'Başarıyla çıkış yapıldı.',
        });

    } catch (error: any) {
        console.error('Logout Handler Hatası:', error);
        return res.status(500).json({
            status: 'error',
            message: 'Sunucu hatası.',
        });
    }
};
