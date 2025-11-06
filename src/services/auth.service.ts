// Dosya: src/services/auth.service.ts
import prisma from '../utils/prisma';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import {
    RegisterInput,
    LoginInput,
    ResetPasswordInput,
    SocialRegisterInput,
    SocialLoginInput,
    SocialMergeInput,
    ProfileCreationInput, // YENİ TİP (Zod'dan)
} from '../utils/zod.schemas';
import {
    generateSixDigitCode,
    sendVerificationCode,
    sendPasswordResetCode,
} from './email.service';
import { verifyGoogleToken } from '../utils/tokenVerifier';
import { signTokens } from '../utils/jwt.utils';
import { Prisma, PrismaClient } from '@prisma/client';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import logger from '../utils/logger';
import { env } from '../utils/env';
// YENİ: Program atama servisimizi import ediyoruz
import { assignInitialProgramToUser } from './program.service';

/**
 * GÜNCELLENDİ: Bu yardımcı fonksiyon, yeni normalize edilmiş şemaya göre
 * tüm profil verilerini (1:1 ve M:N) oluşturur veya günceller.
 */
async function _createNormalizedProfileData(
    tx: Prisma.TransactionClient,
    userId: string,
    input: ProfileCreationInput, // Yeni Zod tipimiz
) {
    logger.info(`[AuthService] Normalize edilmiş profil verisi ${userId} için oluşturuluyor...`);

    // 1. Önceki tüm verileri temizle (Smart Register senaryosu için)
    await tx.userHealthLimitation.deleteMany({ where: { userId } });
    await tx.userGoalPart.deleteMany({ where: { userId } });
    await tx.userAvailableWorkoutEquipment.deleteMany({ where: { userId } });
    await tx.userWorkoutLocation.deleteMany({ where: { userId } });

    // 1:1 ilişkilerde 'deleteMany' 'upsert'den daha güvenlidir (kayıt yoksa hata vermez)
    await tx.userProfile.deleteMany({ where: { userId } });
    await tx.userBody.deleteMany({ where: { userId } });
    await tx.userGoal.deleteMany({ where: { userId } });
    await tx.userSetting.deleteMany({ where: { userId } });
    await tx.userProgramPreference.deleteMany({ where: { userId } });


    // 2. Yeni 1:1 verileri oluştur (Zod şemalarımızla 1:1 eşleşiyor)
    await tx.userProfile.create({ data: { userId, ...input.profile } });
    await tx.userBody.create({ data: { userId, ...input.body } });
    await tx.userGoal.create({ data: { userId, ...input.goal } });
    await tx.userSetting.create({ data: { userId, ...input.settings } });
    await tx.userProgramPreference.create({ data: { userId, ...input.preference } });

    // 3. Yeni M:N verileri oluştur (Artık Int[] değil, String (UUID)[] alıyor)
    await tx.userGoalPart.createMany({
        data: input.targetBodyPartIds.map((id) => ({
            userId,
            goalBodyPartId: id, // Bu artık bir UUID
        })),
    });
    await tx.userAvailableWorkoutEquipment.createMany({
        data: input.availableEquipmentIds.map((id) => ({
            userId,
            workoutEquipmentId: id, // Bu artık bir UUID
        })),
    });
    await tx.userWorkoutLocation.createMany({
        data: input.workoutLocationIds.map((id) => ({
            userId,
            workoutLocationId: id, // Bu artık bir UUID
        })),
    });
    if (input.healthLimitationIds.length > 0) {
        await tx.userHealthLimitation.createMany({
            data: input.healthLimitationIds.map((id) => ({
                userId,
                healthLimitationId: id, // Bu artık bir UUID
            })),
        });
    }
    logger.info(`[AuthService] Profil verisi ${userId} için başarıyla oluşturuldu.`);
}

// === REGISTER USER SERVICE (ANA KAYIT MANTIĞI GÜNCELLENDİ) ===
export const registerUserService = async (
    input: RegisterInput['body'],
    ipAddress: string,
    userAgent: string,
    deviceId: string,
) => {
    const passwordHash = await bcrypt.hash(input.password, 12);

    const existingUser = await prisma.user.findFirst({
        where: {
            OR: [{ email: input.email }, { username: input.username }],
        },
    });

    if (existingUser && existingUser.isEmailVerified) {
        throw new Error('CONFLICT');
    }

    try {
        const { user, tokens } = await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
            let userId: string;

            if (existingUser && !existingUser.isEmailVerified) {
                logger.info(`[AuthService] Smart Registration: ${existingUser.userId} üzerine yazılıyor...`);
                userId = existingUser.userId;

                // Ana User ve Password bilgilerini güncelle
                await tx.user.update({
                    where: { userId },
                    data: {
                        username: input.username,
                        email: input.email,
                        createdAt: new Date(),
                    },
                });
                await tx.userLocalCredential.upsert({
                    where: { userId },
                    create: { userId, passwordHash },
                    update: { passwordHash },
                });

                // GÜNCELLENDİ: Eski _createOrUpdateProfileData yerine _createNormalizedProfileData
                await _createNormalizedProfileData(tx, userId, input);

            } else {
                logger.info(`[AuthService] Clean Registration: ${input.email} için yeni kullanıcı...`);

                const newUser = await tx.user.create({
                    data: {
                        email: input.email,
                        username: input.username,
                        isEmailVerified: false,
                    },
                    select: { userId: true },
                });
                userId = newUser.userId;

                await tx.userLocalCredential.create({
                    data: {
                        userId: userId,
                        passwordHash,
                    },
                });

                // GÜNCELLENDİ: Eski _createOrUpdateProfileData yerine _createNormalizedProfileData
                await _createNormalizedProfileData(tx, userId, input);
            }

            // --- YENİ ADIM (Sizin Stratejiniz) ---
            // Profil verileri oluşturulduktan hemen sonra,
            // bu verilere göre ilk programı atıyoruz.
            // (Hepsi aynı transaction içinde, atomik)
            logger.info(`[AuthService] ${userId} için başlangıç programı atanıyor...`);
            await assignInitialProgramToUser(tx, userId, input);
            // --- YENİ ADIM SONU ---

            // --- MEVCUT ANA MANTIK (Değişiklik Yok) ---
            // (Verification Code, Send Email, Sign Tokens, Save Refresh Token...)
            const code = generateSixDigitCode();
            const hashedCode = await bcrypt.hash(code, 10);
            const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

            await tx.emailVerificationToken.deleteMany({ where: { userId } });
            await tx.emailVerificationToken.create({
                data: {
                    userId,
                    tokenHash: hashedCode,
                    expiresAt,
                    requestIP: ipAddress,
                    userAgent: userAgent,
                },
            });

            await sendVerificationCode(input.email, code);

            const tokens = await signTokens(userId, false);

            const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
            const expiresAtRT = new Date(Date.now() + env.JWT_REFRESH_EXPIRATION_DAYS * 24 * 60 * 60 * 1000);

            await tx.refreshToken.deleteMany({ where: { userId, deviceId } });
            await tx.refreshToken.create({
                data: {
                    userId: userId,
                    tokenHash: refreshTokenHash,
                    expiresAt: expiresAtRT,
                    createdByIP: ipAddress,
                    userAgent: userAgent,
                    deviceId: deviceId,
                },
            });
            // --- MEVCUT ANA MANTIK SONU ---

            return { user: { id: userId, email: input.email }, tokens };
        });

        return { user, tokens };
    } catch (error: unknown) {
        if (error instanceof PrismaClientKnownRequestError) {
            if (error.code === 'P2002') {
                throw new Error('CONFLICT');
            }
        }
        logger.error(error, '[AuthService] Registration Transaction Error');
        throw new Error('Internal Server Error');
    }
};

// === LOGIN SERVICE (ANA MANTIK DEĞİŞMEDİ) ===
export const loginUserService = async (
    input: LoginInput['body'],
    ipAddress: string,
    userAgent: string,
    deviceId: string,
) => {
    const { loginIdentifier, password } = input;

    // (Sorgu aynı, ID'ler veya profille işi yok)
    const user = await prisma.user.findFirst({
        where: {
            OR: [{ email: loginIdentifier }, { username: loginIdentifier }],
        },
        select: {
            userId: true,
            isEmailVerified: true,
            UserLocalCredential: {
                select: {
                    passwordHash: true,
                },
            },
        },
    });

    if (!user) {
        throw new Error('INVALID_CREDENTIALS');
    }
    if (!user.UserLocalCredential) {
        throw new Error('INVALID_CREDENTIALS');
    }
    const passwordMatch = await bcrypt.compare(
        password,
        user.UserLocalCredential.passwordHash,
    );
    if (!passwordMatch) {
        throw new Error('INVALID_CREDENTIALS');
    }

    logger.info(`[AuthService] User logged in: ${user.userId}, Verified: ${user.isEmailVerified}`);

    // (Token mantığı aynı)
    const tokens = await signTokens(user.userId, user.isEmailVerified);

    const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
    const expiresAt = new Date(Date.now() + env.JWT_REFRESH_EXPIRATION_DAYS * 24 * 60 * 60 * 1000);

    await prisma.$transaction([
        prisma.refreshToken.deleteMany({ where: { userId: user.userId, deviceId } }),
        prisma.refreshToken.create({
            data: {
                userId: user.userId,
                tokenHash: refreshTokenHash,
                expiresAt: expiresAt,
                createdByIP: ipAddress,
                userAgent: userAgent,
                deviceId: deviceId,
            },
        }),
    ]);

    return tokens;
};

// === VERIFY EMAIL CODE SERVICE (ANA MANTIK DEĞİŞMEDİ) ===
export const verifyEmailCodeService = async (
    userId: string,
    code: string,
    ipAddress: string,
    userAgent: string,
    deviceId: string,
) => {
    // (Sorgu aynı, ID'ler veya profille işi yok)
    const userWithToken = await prisma.user.findUnique({
        where: { userId },
        include: {
            EmailVerificationToken: {
                where: { isUsed: false },
            },
        },
    });

    const tokenRecord = userWithToken?.EmailVerificationToken[0];

    if (!tokenRecord || tokenRecord.expiresAt < new Date()) {
        throw new Error('INVALID_CODE');
    }
    if (userWithToken?.isEmailVerified) {
        throw new Error('ALREADY_VERIFIED');
    }

    const codeMatch = await bcrypt.compare(code, tokenRecord.tokenHash);

    // (Brute-force koruması aynı)
    if (!codeMatch) {
        const MAX_ATTEMPTS = 5;
        const newAttemptCount = tokenRecord.failedAttempts + 1;

        if (newAttemptCount >= MAX_ATTEMPTS) {
            await prisma.emailVerificationToken.update({
                where: { verificationTokenId: tokenRecord.verificationTokenId },
                data: { isUsed: true, failedAttempts: newAttemptCount },
            });
            logger.warn(
                `[AuthService] VerifyEmail token invalidated: ${userId}`,
            );
        } else {
            await prisma.emailVerificationToken.update({
                where: { verificationTokenId: tokenRecord.verificationTokenId },
                data: { failedAttempts: newAttemptCount },
            });
        }
        throw new Error('INVALID_CODE');
    }

    await prisma.$transaction(async (tx) => {
        await tx.user.update({
            where: { userId },
            data: { isEmailVerified: true },
        });
        await tx.emailVerificationToken.update({
            where: { verificationTokenId: tokenRecord.verificationTokenId },
            data: { isUsed: true },
        });
    });

    // (Token mantığı aynı)
    logger.info(`[AuthService] User verified: ${userId}`);
    const tokens = await signTokens(userId, true);

    const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
    const expiresAt = new Date(Date.now() + env.JWT_REFRESH_EXPIRATION_DAYS * 24 * 60 * 60 * 1000);

    await prisma.$transaction([
        prisma.refreshToken.deleteMany({ where: { userId: userId, deviceId } }),
        prisma.refreshToken.create({
            data: {
                userId: userId,
                tokenHash: refreshTokenHash,
                expiresAt: expiresAt,
                createdByIP: ipAddress,
                userAgent: userAgent,
                deviceId: deviceId,
            },
        }),
    ]);

    return tokens;
};

// === RESEND, FORGOT, RESET (ANA MANTIK DEĞİŞMEDİ) ===
// (Bu fonksiyonlar sadece User, EmailVerificationToken, PasswordResetToken 
// tablolarını kullanır, bu nedenle değişiklik gerekmez)

export const resendVerificationCodeService = async (
    userId: string,
    ipAddress: string,
    userAgent: string,
) => {
    const user = await prisma.user.findUnique({
        where: { userId },
        select: { email: true, isEmailVerified: true },
    });

    if (!user) {
        throw new Error('User not found');
    }
    if (user.isEmailVerified) {
        throw new Error('ALREADY_VERIFIED');
    }

    const code = generateSixDigitCode();
    const hashedCode = await bcrypt.hash(code, 10);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    await prisma.$transaction(async (tx) => {
        await tx.emailVerificationToken.deleteMany({ where: { userId } });
        await tx.emailVerificationToken.create({
            data: {
                userId,
                tokenHash: hashedCode,
                expiresAt,
                requestIP: ipAddress,
                userAgent: userAgent,
            },
        });
    });

    await sendVerificationCode(user.email, code);
    return;
};

export const forgotPasswordService = async (
    email: string,
    ipAddress: string,
    userAgent: string,
) => {
    const user = await prisma.user.findUnique({
        where: { email },
    });

    if (!user || !user.isEmailVerified) {
        logger.warn(`[AuthService] Forgot PWD: Silent exit (User not found or unverified): ${email}`);
        return;
    }

    const code = generateSixDigitCode();
    const hashedCode = await bcrypt.hash(code, 10);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await prisma.$transaction(async (tx) => {
        await tx.passwordResetToken.deleteMany({
            where: { userId: user.userId },
        });
        await tx.passwordResetToken.create({
            data: {
                userId: user.userId,
                tokenHash: hashedCode,
                expiresAt,
                requestIP: ipAddress,
                userAgent: userAgent,
            },
        });
    });

    await sendPasswordResetCode(user.email, code);
    return;
};

export const resetPasswordService = async (input: ResetPasswordInput['body']) => {
    const { email, code, newPassword } = input;

    const userWithToken = await prisma.user.findUnique({
        where: { email },
        include: {
            PasswordResetToken: {
                where: {
                    isUsed: false,
                    expiresAt: { gt: new Date() },
                },
            },
            UserLocalCredential: true,
        },
    });

    const tokenRecord = userWithToken?.PasswordResetToken[0];
    if (!tokenRecord) {
        throw new Error('INVALID_CODE');
    }

    const codeMatch = await bcrypt.compare(code, tokenRecord.tokenHash);

    if (!codeMatch) {
        // (Brute-force koruması aynı)
        const MAX_ATTEMPTS = 5;
        const newAttemptCount = tokenRecord.failedAttempts + 1;

        if (newAttemptCount >= MAX_ATTEMPTS) {
            await prisma.passwordResetToken.update({
                where: { resetTokenId: tokenRecord.resetTokenId },
                data: { isUsed: true, failedAttempts: newAttemptCount },
            });
            logger.warn(
                `[AuthService] ResetPassword token invalidated: ${userWithToken.userId}`,
            );
        } else {
            await prisma.passwordResetToken.update({
                where: { resetTokenId: tokenRecord.resetTokenId },
                data: { failedAttempts: newAttemptCount },
            });
        }
        throw new Error('INVALID_CODE');
    }

    if (!userWithToken.UserLocalCredential) {
        throw new Error('NO_LOCAL_ACCOUNT');
    }

    const newPasswordHash = await bcrypt.hash(newPassword, 12);

    await prisma.$transaction(async (tx) => {
        await tx.userLocalCredential.update({
            where: { userId: userWithToken.userId },
            data: { passwordHash: newPasswordHash },
        });
        await tx.passwordResetToken.update({
            where: { resetTokenId: tokenRecord.resetTokenId },
            data: { isUsed: true },
        });
    });

    logger.info(`[AuthService] User password reset: ${userWithToken.userId}`);
    return;
};


// === SOCIAL REGISTER SERVICE (GÜNCELLENDİ) ===
export const socialRegisterService = async (
    input: SocialRegisterInput['body'],
    ipAddress: string,
    userAgent: string,
    deviceId: string,
) => {
    let providerData: {
        email: string;
        externalId: string;
        emailVerified: boolean;
    };
    if (input.provider === 'GOOGLE') {
        providerData = await verifyGoogleToken(input.providerToken);
        if (!providerData.emailVerified) {
            throw new Error('TOKEN_VERIFICATION_FAILED');
        }
    } else {
        throw new Error('Provider not yet supported');
    }

    const existingUser = await prisma.user.findUnique({
        where: { email: providerData.email },
        include: { UserLocalCredential: true },
    });

    if (existingUser && existingUser.isEmailVerified && existingUser.UserLocalCredential) {
        throw new Error('CONFLICT');
    }

    try {
        const tokens = await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
            let userId: string;

            if (existingUser && !existingUser.isEmailVerified) {
                logger.info(`[AuthService] Social Registration (Overwrite): ${existingUser.userId}...`);
                userId = existingUser.userId;

                await tx.user.update({
                    where: { userId },
                    data: {
                        isEmailVerified: true,
                        createdAt: new Date(),
                    },
                });
            } else {
                logger.info(`[AuthService] Social Registration (Clean): ${providerData.email}...`);

                const newUser = await tx.user.create({
                    data: {
                        email: providerData.email,
                        username: input.username,
                        isEmailVerified: true,
                    },
                    select: { userId: true },
                });
                userId = newUser.userId;
            }

            // GÜNCELLENDİ: Profil verisi oluşturma
            await _createNormalizedProfileData(tx, userId, input);

            // YENİ ADIM: Program atama
            logger.info(`[AuthService] ${userId} için sosyal kayıt programı atanıyor...`);
            await assignInitialProgramToUser(tx, userId, input);

            // --- MEVCUT ANA MANTIK (Değişiklik Yok) ---
            await tx.userExternalLogin.upsert({
                where: {
                    loginProvider_providerKey: {
                        loginProvider: input.provider,
                        providerKey: providerData.externalId,
                    },
                },
                create: {
                    userId,
                    loginProvider: input.provider,
                    providerKey: providerData.externalId,
                },
                update: {
                    userId,
                },
            });

            const tokens = await signTokens(userId, true);

            const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
            const expiresAt = new Date(Date.now() + env.JWT_REFRESH_EXPIRATION_DAYS * 24 * 60 * 60 * 1000);

            await tx.refreshToken.deleteMany({ where: { userId, deviceId } });
            await tx.refreshToken.create({
                data: {
                    userId: userId,
                    tokenHash: refreshTokenHash,
                    expiresAt: expiresAt,
                    createdByIP: ipAddress,
                    userAgent: userAgent,
                    deviceId: deviceId,
                },
            });
            // --- MEVCUT ANA MANTIK SONU ---

            return tokens;
        });

        return tokens;
    } catch (error: unknown) {
        if (error instanceof PrismaClientKnownRequestError && error.code === 'P2002') {
            throw new Error('CONFLICT');
        }
        if (error instanceof Error && (error.message === 'TOKEN_VERIFICATION_FAILED' || error.message === 'CONFLICT')) {
            throw error;
        }
        logger.error(error, '[AuthService] Social Registration Transaction Error');
        throw new Error('Internal Server Error');
    }
};

// === SOCIAL LOGIN & MERGE (ANA MANTIK DEĞİŞMEDİ) ===
// (Bu fonksiyonlar profil oluşturma ile ilgilenmez, sadece kimlik doğrular)

export const socialLoginService = async (
    input: SocialLoginInput['body'],
    ipAddress: string,
    userAgent: string,
    deviceId: string,
) => {
    let providerData: {
        email: string;
        externalId: string;
        emailVerified: boolean;
    };
    if (input.provider === 'GOOGLE') {
        providerData = await verifyGoogleToken(input.providerToken);
        if (!providerData.emailVerified) {
            throw new Error('TOKEN_VERIFICATION_FAILED');
        }
    } else {
        throw new Error('Provider not yet supported');
    }

    let user = await prisma.user.findFirst({
        where: {
            UserExternalLogin: {
                some: {
                    loginProvider: input.provider,
                    providerKey: providerData.externalId,
                },
            },
        },
        include: {
            UserLocalCredential: true,
            UserExternalLogin: true,
        },
    });

    if (!user) {
        const userByEmail = await prisma.user.findUnique({
            where: { email: providerData.email },
            include: {
                UserLocalCredential: true,
                UserExternalLogin: true,
            },
        });

        if (!userByEmail) {
            throw new Error('USER_NOT_FOUND');
        }
        user = userByEmail;
    }

    if (
        user.isEmailVerified &&
        user.UserLocalCredential &&
        !user.UserExternalLogin.some((l) => l.loginProvider === input.provider)
    ) {
        throw new Error('ACCOUNT_MERGE_REQUIRED');
    }

    logger.info(`[AuthService] Social user logged in: ${user.userId}, Verified: ${user.isEmailVerified}`);

    const tokens = await signTokens(user.userId, true);
    const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
    const expiresAt = new Date(Date.now() + env.JWT_REFRESH_EXPIRATION_DAYS * 24 * 60 * 60 * 1000);

    await prisma.$transaction(async (tx) => {
        await tx.refreshToken.deleteMany({ where: { userId: user.userId, deviceId } });
        await tx.refreshToken.create({
            data: {
                userId: user.userId,
                tokenHash: refreshTokenHash,
                expiresAt: expiresAt,
                createdByIP: ipAddress,
                userAgent: userAgent,
                deviceId: deviceId,
            },
        });

        if (!user.isEmailVerified) {
            await tx.user.update({
                where: { userId: user.userId },
                data: { isEmailVerified: true },
            });
        }

        if (!user.UserExternalLogin.some((l) => l.loginProvider === input.provider)) {
            await tx.userExternalLogin.create({
                data: {
                    userId: user.userId,
                    loginProvider: input.provider,
                    providerKey: providerData.externalId,
                },
            });
        }
    });

    return tokens;
};

export const socialMergeService = async (
    input: SocialMergeInput['body'],
    ipAddress: string,
    userAgent: string,
    deviceId: string,
) => {
    let providerData: {
        email: string;
        externalId: string;
        emailVerified: boolean;
    };

    if (input.provider === 'GOOGLE') {
        providerData = await verifyGoogleToken(input.providerToken);
        if (!providerData.emailVerified) {
            throw new Error('TOKEN_VERIFICATION_FAILED');
        }
    } else {
        throw new Error('Provider not yet supported');
    }

    const user = await prisma.user.findUnique({
        where: { email: providerData.email },
        include: { UserLocalCredential: true },
    });

    if (!user || !user.UserLocalCredential) {
        throw new Error('INVALID_CREDENTIALS');
    }

    const passwordMatch = await bcrypt.compare(
        input.password,
        user.UserLocalCredential.passwordHash,
    );

    if (!passwordMatch) {
        throw new Error('INVALID_CREDENTIALS');
    }

    logger.info(`[AuthService] Merging account: ${user.userId} -> ${input.provider}`);

    const tokens = await signTokens(user.userId, true);
    const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
    const expiresAt = new Date(Date.now() + env.JWT_REFRESH_EXPIRATION_DAYS * 24 * 60 * 60 * 1000);

    await prisma.$transaction(async (tx) => {
        await tx.refreshToken.deleteMany({ where: { userId: user.userId, deviceId } });
        await tx.refreshToken.create({
            data: {
                userId: user.userId,
                tokenHash: refreshTokenHash,
                expiresAt: expiresAt,
                createdByIP: ipAddress,
                userAgent: userAgent,
                deviceId: deviceId,
            },
        });

        if (!user.isEmailVerified) {
            await tx.user.update({
                where: { userId: user.userId },
                data: { isEmailVerified: true },
            });
        }

        await tx.userExternalLogin.upsert({
            where: {
                loginProvider_providerKey: {
                    loginProvider: input.provider,
                    providerKey: providerData.externalId,
                },
            },
            create: {
                userId: user.userId,
                loginProvider: input.provider,
                providerKey: providerData.externalId,
            },
            update: {},
        });
    });

    return tokens;
};

// === REFRESH & LOGOUT (ANA MANTIK DEĞİŞMEDİ) ===
// (Bu fonksiyonlar da profille ilgilenmez)

export const refreshTokenService = async (
    refreshToken: string,
    deviceId: string,
    ipAddress: string,
    userAgent: string,
) => {
    const JWT_SECRET = env.JWT_SECRET;

    let payload: { sub: string };
    try {
        payload = jwt.verify(refreshToken, JWT_SECRET) as { sub: string };
    } catch (error) {
        logger.warn(error, '[AuthService] Invalid refresh token (verify failed)');
        throw new Error('INVALID_REFRESH_TOKEN');
    }

    const userId = payload.sub;

    const tokenRecord = await prisma.refreshToken.findFirst({
        where: {
            userId: userId,
            deviceId: deviceId,
            isUsed: false,
            expiresAt: { gt: new Date() },
        },
    });

    if (!tokenRecord) {
        throw new Error('INVALID_REFRESH_TOKEN');
    }

    const tokenMatch = await bcrypt.compare(refreshToken, tokenRecord.tokenHash);
    if (!tokenMatch) {
        throw new Error('INVALID_REFRESH_TOKEN');
    }

    logger.info(`[AuthService] Refreshing token for: ${userId}, Device: ${deviceId}`);

    const user = await prisma.user.findUnique({
        where: { userId },
        select: { isEmailVerified: true },
    });
    if (!user) {
        throw new Error('INVALID_REFRESH_TOKEN');
    }

    const newTokens = await signTokens(userId, user.isEmailVerified);
    const newRefreshTokenHash = await bcrypt.hash(newTokens.refreshToken, 10);
    const newExpiresAt = new Date(Date.now() + env.JWT_REFRESH_EXPIRATION_DAYS * 24 * 60 * 60 * 1000);

    await prisma.$transaction(async (tx) => {
        await tx.refreshToken.deleteMany({
            where: {
                userId: userId,
                deviceId: deviceId,
            },
        });
        await tx.refreshToken.create({
            data: {
                userId: userId,
                tokenHash: newRefreshTokenHash,
                expiresAt: newExpiresAt,
                createdByIP: ipAddress,
                userAgent: userAgent,
                deviceId: deviceId,
            },
        });
    });

    return newTokens;
};

export const logoutUserService = async (userId: string, deviceId: string) => {
    await prisma.refreshToken.deleteMany({
        where: {
            userId: userId,
            deviceId: deviceId,
        },
    });

    logger.info(`[AuthService] User logged out (device: ${deviceId}): ${userId}`);
    return;
};