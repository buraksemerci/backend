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
    ProfileCreationInput,
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
import { assignInitialProgramToUser } from './program.service';

/**
 * (MEVCUT YARDIMCI - Değişiklik Yok)
 * GÜNCELLENDİ: Bu yardımcı fonksiyon, yeni normalize edilmiş şemaya göre
 * tüm profil verilerini (1:1 ve M:N) oluşturur veya günceller.
 */
async function _createNormalizedProfileData(
    tx: Prisma.TransactionClient,
    userId: string,
    input: ProfileCreationInput,
) {
    logger.info(`[AuthService] Normalize edilmiş profil verisi ${userId} için oluşturuluyor...`);

    // 1. Önceki tüm verileri temizle (Smart Register senaryosu için)
    await tx.userHealthLimitation.deleteMany({ where: { userId } });
    await tx.userGoalPart.deleteMany({ where: { userId } });
    await tx.userAvailableWorkoutEquipment.deleteMany({ where: { userId } });
    await tx.userWorkoutLocation.deleteMany({ where: { userId } });

    await tx.userProfile.deleteMany({ where: { userId } });
    await tx.userBody.deleteMany({ where: { userId } });
    await tx.userGoal.deleteMany({ where: { userId } });
    await tx.userSetting.deleteMany({ where: { userId } });
    await tx.userProgramPreference.deleteMany({ where: { userId } });
    await tx.userProgramAssignment.deleteMany({ where: { userId } });


    // 2. Yeni 1:1 verileri oluştur
    await tx.userProfile.create({ data: { userId, ...input.profile } });
    await tx.userBody.create({ data: { userId, ...input.body } });
    await tx.userGoal.create({ data: { userId, ...input.goal } });
    await tx.userSetting.create({ data: { userId, ...input.settings } });
    await tx.userProgramPreference.create({ data: { userId, ...input.preference } });

    // 3. Yeni M:N verileri oluştur
    await tx.userGoalPart.createMany({
        data: input.targetBodyPartIds.map((id) => ({
            userId,
            goalBodyPartId: id,
        })),
    });
    await tx.userAvailableWorkoutEquipment.createMany({
        data: input.availableEquipmentIds.map((id) => ({
            userId,
            workoutEquipmentId: id,
        })),
    });
    await tx.userWorkoutLocation.createMany({
        data: input.workoutLocationIds.map((id) => ({
            userId,
            workoutLocationId: id,
        })),
    });
    if (input.healthLimitationIds.length > 0) {
        await tx.userHealthLimitation.createMany({
            data: input.healthLimitationIds.map((id) => ({
                userId,
                healthLimitationId: id,
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

    // --- YENİ MANTIK BAŞLANGICI (SİZİN ÖNERİNİZ) ---

    // Kural 1: Önce SADECE 'username'i kontrol et (Transaction dışında)
    const existingUserByUsername = await prisma.user.findUnique({
        where: { username: input.username },
    });

    if (existingUserByUsername) {
        // "kullanıcı adı zaten kullanımdaysa her türlü hata verecek"
        logger.warn(`[AuthService] Kayıt engellendi: ${input.username} kullanıcı adı zaten alınmış.`);
        throw new Error('CONFLICT');
    }

    // 'username' müsait olduğuna göre, 'email' durumunu kontrol etmek için transaction başlat
    // --- YENİ MANTIK SONU ---

    try {
        const { user, tokens } = await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
            let userId: string;

            // Kural 2: Şimdi 'email'i kontrol et (Transaction içinde)
            const existingUserByEmail = await tx.user.findUnique({
                where: { email: input.email },
            });

            if (existingUserByEmail) {

                // Durum A: E-posta mevcut VE doğrulanmış (CONFLICT)
                if (existingUserByEmail.isEmailVerified) {
                    // "sistemde onlanmış bir e posta ile denenmesi durumunda yine hata verecek"
                    logger.warn(`[AuthService] Kayıt engellendi: ${input.email} e-postası zaten doğrulanmış.`);
                    throw new Error('CONFLICT');
                }

                // Durum B: E-posta mevcut AMA doğrulanmamış ("Akıllı Kayıt")
                else {
                    // "kullanıcı adı boşsa ve e posta onaylanmamışsa akıllı kayıt olacak"
                    logger.info(`[AuthService] Smart Registration: ${existingUserByEmail.userId} üzerine yazılıyor...`);
                    userId = existingUserByEmail.userId;

                    // 'username'in boş olduğunu zaten dışarıda kontrol ettik.
                    // Şimdi bu e-posta kaydını yeni 'username' ile GÜNCELLE.
                    await tx.user.update({
                        where: { userId },
                        data: {
                            username: input.username, // Yeni (ve müsait olduğu bilinen) username
                            email: input.email,
                            createdAt: new Date(),
                        },
                    });

                    // Şifreyi güncelle/oluştur
                    await tx.userLocalCredential.upsert({
                        where: { userId },
                        create: { userId, passwordHash },
                        update: { passwordHash },
                    });

                    // Profil verilerini yeniden oluştur
                    await _createNormalizedProfileData(tx, userId, input);
                }
            }

            // Durum C: E-posta mevcut değil ("Temiz Kayıt")
            else {
                // Hem 'username' hem de 'email' yeni.
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

                await _createNormalizedProfileData(tx, userId, input);
            }

            // --- MEVCUT ANA MANTIK (Değişiklik Yok) ---
            // (Verification Code, Send Email, Sign Tokens, Save Refresh Token...)
            logger.info(`[AuthService] ${userId} için başlangıç programı atanıyor...`);
            await assignInitialProgramToUser(tx, userId, input);

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
        // P2002 (Unique constraint) hatası bu yeni mantıkta
        // SADECE 'username' kontrolünden kaçan bir race condition (yarış durumu)
        // veya 'email'de (çok düşük ihtimal) olursa tetiklenir.
        if (error instanceof PrismaClientKnownRequestError) {
            if (error.code === 'P2002') {
                logger.warn(`[AuthService] P2002 Unique Constraint Hatası (muhtemelen race condition): ${error.meta?.target}`);
                throw new Error('CONFLICT');
            }
        }
        // Manuel olarak fırlatılan CONFLICT hatalarını yakala
        if (error instanceof Error && error.message === 'CONFLICT') {
            throw error;
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

    // --- YENİ MANTIK (Aynen registerUserService'teki gibi) ---
    // 1. Önce 'username'i kontrol et
    const existingUserByUsername = await prisma.user.findUnique({
        where: { username: input.username },
    });

    if (existingUserByUsername) {
        logger.warn(`[AuthService] Sosyal Kayıt engellendi: ${input.username} kullanıcı adı zaten alınmış.`);
        throw new Error('CONFLICT');
    }

    try {
        const tokens = await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
            let userId: string;

            // 2. 'username' müsait, şimdi 'email'i kontrol et
            const existingUserByEmail = await tx.user.findUnique({
                where: { email: providerData.email },
                include: { UserLocalCredential: true }
            });

            // Durum A: E-posta mevcut VE lokal hesabı var (doğrulanmış veya onaysız)
            if (existingUserByEmail && existingUserByEmail.UserLocalCredential) {
                // Bu, lokal bir hesaptır ve sosyal kayıtla üzerine yazılmamalıdır.
                // (Eğer onaysızsa, kullanıcının önce 'socialMerge' yapması gerekir)
                logger.warn(`[AuthService] Sosyal Kayıt engellendi: ${providerData.email} lokal bir hesaba ait.`);
                throw new Error('CONFLICT');
            }

            // Durum B: E-posta mevcut AMA lokal hesabı yok ("Akıllı Sosyal Kayıt")
            // (Bu, daha önce başka bir sosyal sağlayıcı ile açılmış olabilir)
            else if (existingUserByEmail && !existingUserByEmail.UserLocalCredential) {
                logger.info(`[AuthService] Social Registration (Smart): ${existingUserByEmail.userId} üzerine yazılıyor...`);
                userId = existingUserByEmail.userId;

                // 'username'i güncelle (çünkü ilk sosyal kayıtta bu alınmamış olabilir)
                // ve doğrulanmış say
                await tx.user.update({
                    where: { userId },
                    data: {
                        username: input.username,
                        isEmailVerified: true,
                    },
                });
            }

            // Durum C: E-posta mevcut değil ("Temiz Sosyal Kayıt")
            else {
                logger.info(`[AuthService] Social Registration (Clean): ${providerData.email}...`);

                const newUser = await tx.user.create({
                    data: {
                        email: providerData.email,
                        username: input.username,
                        isEmailVerified: true, // Sosyalden geldiği için
                    },
                    select: { userId: true }
                });
                userId = newUser.userId;
            }

            // --- YENİ MANTIK SONU ---

            // Profil verisi oluşturma
            await _createNormalizedProfileData(tx, userId, input);

            // Program atama
            logger.info(`[AuthService] ${userId} için sosyal kayıt programı atanıyor...`);
            await assignInitialProgramToUser(tx, userId, input);

            // Harici (External) Login kaydını oluştur/güncelle
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
                    userId, // (Gerekirse 'userId'yi güncelle, örn: e-posta birleştiyse)
                },
            });

            // Tokenları imzala ve kaydet
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

            return tokens;
        });

        return tokens;
    } catch (error: unknown) {
        if (error instanceof PrismaClientKnownRequestError && error.code === 'P2002') {
            // (Bu, 'update' veya 'create' sırasındaki benzersizlik hatasını yakalar)
            logger.warn(`[AuthService] Sosyal Kayıt P2002 Hatası: ${error.meta?.target}`);
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