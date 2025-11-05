// Dosya: src/controllers/auth.controller.ts
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
import logger from '../utils/logger';

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
            data: tokens,
        });
    } catch (error: any) {
        if (error.message === 'CONFLICT') {
            return res.status(409).json({
                status: 'error',
                code: 'AUTH_CONFLICT',
            });
        }
        logger.error(error, 'Register Handler Error');
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
            data: tokens,
        });
    } catch (error: any) {
        if (error.message === 'INVALID_CREDENTIALS') {
            return res.status(401).json({
                status: 'error',
                code: 'AUTH_INVALID_CREDENTIALS',
            });
        }
        logger.error(error, 'Login Handler Error');
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
            return res.status(403).json({ status: 'error', code: 'AUTH_UNAUTHORIZED' });
        }
        const userId = req.user.sub;
        const { code, deviceId } = req.body;
        const ipAddress = req.ip || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';

        const tokens = await verifyEmailCodeService(userId, code, ipAddress, userAgent, deviceId);

        return res.status(200).json({
            status: 'success',
            data: tokens,
        });
    } catch (error: any) {
        if (error.message === 'INVALID_CODE') {
            return res.status(400).json({
                status: 'error',
                code: 'AUTH_INVALID_CODE',
            });
        }
        if (error.message === 'ALREADY_VERIFIED') {
            return res.status(400).json({
                status: 'error',
                code: 'AUTH_ALREADY_VERIFIED',
            });
        }
        logger.error(error, 'Verify Code Handler Error');
        throw error;
    }
};

// === RESEND CODE HANDLER ===
export const resendCodeHandler = async (req: Request, res: Response) => {
    try {
        if (!req.user) {
            return res.status(403).json({ status: 'error', code: 'AUTH_UNAUTHORIZED' });
        }
        const userId = req.user.sub;
        const ipAddress = req.ip || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';

        await resendVerificationCodeService(userId, ipAddress, userAgent);

        return res.status(200).json({
            status: 'success',
        });
    } catch (error: any) {
        if (error.message === 'ALREADY_VERIFIED') {
            return res.status(400).json({
                status: 'error',
                code: 'AUTH_ALREADY_VERIFIED',
            });
        }
        logger.error(error, 'Resend Code Handler Error');
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

        // Always return 200 to prevent email enumeration
        return res.status(200).json({
            status: 'success',
        });
    } catch (error: any) {
        logger.error(error, 'Forgot Password Handler Error');
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
        });
    } catch (error: any) {
        if (error.message === 'INVALID_CODE') {
            return res.status(400).json({
                status: 'error',
                code: 'AUTH_INVALID_CODE',
            });
        }
        if (error.message === 'NO_LOCAL_ACCOUNT') {
            return res.status(400).json({
                status: 'error',
                code: 'AUTH_NO_LOCAL_ACCOUNT',
            });
        }
        logger.error(error, 'Reset Password Handler Error');
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
            data: tokens,
        });
    } catch (error: any) {
        if (error.message === 'TOKEN_VERIFICATION_FAILED') {
            return res.status(401).json({
                status: 'error',
                code: 'AUTH_SOCIAL_TOKEN_INVALID',
            });
        }
        if (error.message === 'CONFLICT') {
            return res.status(409).json({
                status: 'error',
                code: 'AUTH_CONFLICT',
            });
        }
        logger.error(error, 'Social Register Handler Error');
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
            data: tokens,
        });
    } catch (error: any) {
        if (error.message === 'TOKEN_VERIFICATION_FAILED') {
            return res.status(401).json({
                status: 'error',
                code: 'AUTH_SOCIAL_TOKEN_INVALID',
            });
        }
        if (error.message === 'USER_NOT_FOUND') {
            return res.status(404).json({
                status: 'error',
                code: 'AUTH_USER_NOT_FOUND',
            });
        }
        if (error.message === 'ACCOUNT_MERGE_REQUIRED') {
            return res.status(409).json({
                status: 'error',
                code: 'AUTH_ACCOUNT_MERGE_REQUIRED'
            });
        }
        logger.error(error, 'Social Login Handler Error');
        throw error;
    }
};

// === SOCIAL MERGE HANDLER ===
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
            data: tokens,
        });

    } catch (error: any) {
        if (error.message === 'TOKEN_VERIFICATION_FAILED') {
            return res.status(401).json({
                status: 'error',
                code: 'AUTH_SOCIAL_TOKEN_INVALID',
            });
        }
        if (error.message === 'INVALID_CREDENTIALS') {
            return res.status(401).json({
                status: 'error',
                code: 'AUTH_INVALID_CREDENTIALS',
            });
        }
        logger.error(error, 'Social Merge Handler Error');
        throw error;
    }
};

// === REFRESH TOKEN HANDLER ===
export const refreshTokenHandler = async (
    req: Request<{}, {}, RefreshInput['body']>,
    res: Response
) => {
    try {
        const ipAddress = req.ip || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';

        const tokens = await refreshTokenService(req.body.refreshToken, req.body.deviceId, ipAddress, userAgent);

        return res.status(200).json({
            status: 'success',
            data: tokens,
        });

    } catch (error: any) {
        if (error.message === 'INVALID_REFRESH_TOKEN') {
            return res.status(401).json({
                status: 'error',
                code: 'AUTH_INVALID_REFRESH_TOKEN',
            });
        }
        logger.error(error, 'Refresh Token Handler Error');
        throw error;
    }
};

// === LOGOUT HANDLER ===
export const logoutUserHandler = async (req: Request<{}, {}, LogoutInput['body']>, res: Response) => {
    try {
        if (!req.user) {
            return res.status(403).json({ status: 'error', code: 'AUTH_UNAUTHORIZED' });
        }
        const userId = req.user.sub;
        const { deviceId } = req.body;

        await logoutUserService(userId, deviceId);

        return res.status(200).json({
            status: 'success',
        });

    } catch (error: any) {
        logger.error(error, 'Logout Handler Error');
        throw error;
    }
};