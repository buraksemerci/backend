// src/services/auth.service.ts
import prisma from "../utils/prisma";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import {
    RegisterInput,
    LoginInput,
    VerifyCodeInput,
    ForgotPasswordInput,
    ResetPasswordInput,
    SocialRegisterInput,
    SocialLoginInput,
    SocialMergeInput,
    ProfileCreationInput
} from '../utils/zod.schemas';
import {
    generateSixDigitCode,
    sendVerificationCode,
    sendPasswordResetCode
} from './email.service';
import { verifyGoogleToken } from '../utils/tokenVerifier';
import { signTokens } from '../utils/jwt.utils';
import {
    Prisma,
    PrismaClient,
    UserExternalLogin
} from '@prisma/client';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import logger from '../utils/logger'; // <-- YENİ
import { env } from '../utils/env'; // <-- YENİ


async function _createOrUpdateProfileData(
    tx: Prisma.TransactionClient,
    userId: string,
    input: ProfileCreationInput
) {
    logger.info(`Kullanıcı ${userId} için profil verileri oluşturuluyor/güncelleniyor...`);

    // 1. Önceki tüm verileri temizle (Overwrite/İşgal senaryosu için)
    // (deleteMany kullanmak, kayıt yoksa hata vermez, delete verir)
    await tx.userHealthLimitation.deleteMany({ where: { userId } });
    await tx.userGoalPart.deleteMany({ where: { userId } });
    await tx.userAvailableWorkoutEquipment.deleteMany({ where: { userId } });
    await tx.userWorkoutLocation.deleteMany({ where: { userId } });
    await tx.userProfile.deleteMany({ where: { userId } });
    await tx.userBody.deleteMany({ where: { userId } });
    await tx.userGoal.deleteMany({ where: { userId } });
    await tx.userSetting.deleteMany({ where: { userId } });

    // 2. Yeni 1:1 verileri oluştur
    await tx.userProfile.create({ data: { userId, ...input.profile } });
    await tx.userBody.create({ data: { userId, ...input.body } });
    await tx.userGoal.create({ data: { userId, ...input.goal } });
    await tx.userSetting.create({ data: { userId, ...input.settings } });

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
    logger.info(`Kullanıcı ${userId} için profil verileri başarıyla oluşturuldu.`);
}

// === REGISTER USER SERVICE ===
export const registerUserService = async (
    input: RegisterInput['body'],
    ipAddress: string,
    userAgent: string,
    deviceId: string
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
                logger.info(`Akıllı Kayıt: ${existingUser.userId} ID'li doğrulanmamış hesap üzerine yazılıyor...`);
                userId = existingUser.userId;

                // Ana User ve Şifresini GÜNCELLE
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

            } else {
                logger.info(`Temiz Kayıt: ${input.email} için yeni kullanıcı oluşturuluyor...`);

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
            }

            // --- DEĞİŞİKLİK: YARDIMCI FONKSİYON ÇAĞRILDI ---
            // Kod tekrarı olan profil oluşturma mantığı buradaydı, artık fonksiyonda.
            await _createOrUpdateProfileData(tx, userId, input);
            // --- DEĞİŞİKLİK SONU ---

            // 7. Doğrulama Kodu
            const code = generateSixDigitCode();
            const hashedCode = await bcrypt.hash(code, 10);
            const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 dakika

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

            // 8. E-posta Gönder
            await sendVerificationCode(input.email, code);

            // 9. JWT Oluştur
            const tokens = await signTokens(userId, false);

            // 10. Refresh Token'ı Kaydet
            const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
            const expiresAtRT = new Date(Date.now() + (env.JWT_REFRESH_EXPIRATION_DAYS * 24 * 60 * 60 * 1000));

            await tx.refreshToken.deleteMany({ where: { userId, deviceId } });
            await tx.refreshToken.create({
                data: {
                    userId: userId,
                    tokenHash: refreshTokenHash,
                    expiresAt: expiresAtRT,
                    createdByIP: ipAddress,
                    userAgent: userAgent,
                    deviceId: deviceId
                }
            });

            return { user: { id: userId, email: input.email }, tokens };
        });

        return { user, tokens };

    } catch (error: unknown) {
        if (error instanceof PrismaClientKnownRequestError) {
            if (error.code === 'P2002') {
                throw new Error('CONFLICT');
            }
        }
        logger.error(error, 'Kayıt Transaction Hatası');
        throw new Error('Internal Server Error');
    }
};

// === LOGIN SERVİSİ ===
export const loginUserService = async (
    input: LoginInput['body'],
    ipAddress: string,
    userAgent: string,
    deviceId: string
) => {
    const { loginIdentifier, password } = input;

    const user = await prisma.user.findFirst({
        where: {
            OR: [
                { email: loginIdentifier },
                { username: loginIdentifier }
            ],
        },
        include: {
            UserLocalCredential: true,
        },
    });

    if (!user) {
        throw new Error('INVALID_CREDENTIALS');
    }
    if (!user.UserLocalCredential) {
        // Bu, muhtemelen bir sosyal kayıt kullanıcısıdır, yerel şifresi yoktur.
        throw new Error('INVALID_CREDENTIALS');
    }
    const passwordMatch = await bcrypt.compare(
        password,
        user.UserLocalCredential.passwordHash
    );
    if (!passwordMatch) {
        throw new Error('INVALID_CREDENTIALS');
    }

    logger.info(`Kullanıcı giriş yaptı: ${user.userId}, Doğrulanmış: ${user.isEmailVerified}`);
    const tokens = await signTokens(user.userId, user.isEmailVerified);

    const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
    const expiresAt = new Date(Date.now() + (env.JWT_REFRESH_EXPIRATION_DAYS * 24 * 60 * 60 * 1000));

    await prisma.$transaction([
        prisma.refreshToken.deleteMany({ where: { userId: user.userId, deviceId } }),
        prisma.refreshToken.create({
            data: {
                userId: user.userId,
                tokenHash: refreshTokenHash,
                expiresAt: expiresAt,
                createdByIP: ipAddress,
                userAgent: userAgent,
                deviceId: deviceId
            }
        })
    ]);

    return tokens;
};

// === VERIFY EMAIL CODE SERVİSİ ===
export const verifyEmailCodeService = async (
    userId: string,
    code: string,
    ipAddress: string,
    userAgent: string,
    deviceId: string
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

    logger.info(`Kullanıcı doğrulandı: ${userId}`);
    const tokens = await signTokens(userId, true);

    const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
    const expiresAt = new Date(Date.now() + (env.JWT_REFRESH_EXPIRATION_DAYS * 24 * 60 * 60 * 1000));

    await prisma.$transaction([
        prisma.refreshToken.deleteMany({ where: { userId: userId, deviceId } }),
        prisma.refreshToken.create({
            data: {
                userId: userId,
                tokenHash: refreshTokenHash,
                expiresAt: expiresAt,
                createdByIP: ipAddress,
                userAgent: userAgent,
                deviceId: deviceId
            }
        })
    ]);

    return tokens;
};

// === RESEND VERIFICATION CODE SERVİSİ ===
export const resendVerificationCodeService = async (
    userId: string,
    ipAddress: string,
    userAgent: string
) => {
    const user = await prisma.user.findUnique({
        where: { userId },
        select: { email: true, isEmailVerified: true },
    });

    if (!user) {
        throw new Error('User not found'); // Bu global handler'a gidecek
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

// === FORGOT PASSWORD SERVİSİ ===
export const forgotPasswordService = async (
    email: string,
    ipAddress: string,
    userAgent: string
) => {
    const user = await prisma.user.findUnique({
        where: { email },
    });

    if (!user || !user.isEmailVerified) {
        logger.warn(`[Forgot PWD]: Sessiz çıkış (Kullanıcı bulunamadı veya doğrulanmamış): ${email}`);
        return;
    }

    const code = generateSixDigitCode();
    const hashedCode = await bcrypt.hash(code, 10);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 dakika

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

// === RESET PASSWORD SERVİSİ ===
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

    logger.info(`Kullanıcı şifresi sıfırlandı: ${userWithToken.userId}`);
    return;
};

// === SOCIAL REGISTER SERVİSİ ===
export const socialRegisterService = async (
    input: SocialRegisterInput['body'],
    ipAddress: string,
    userAgent: string,
    deviceId: string
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
        // TODO: Apple ve Facebook doğrulaması buraya eklenecek
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
                logger.info(`Sosyal Kayıt (Overwrite): ${existingUser.userId} ID'li doğrulanmamış hesap üzerine yazılıyor...`);
                userId = existingUser.userId;

                await tx.user.update({
                    where: { userId },
                    data: {
                        isEmailVerified: true,
                        createdAt: new Date(),
                    },
                });

            } else {
                logger.info(`Sosyal Kayıt (Temiz): ${providerData.email} için yeni kullanıcı oluşturuluyor...`);

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

            // --- DEĞİŞİKLİK: YARDIMCI FONKSİYON ÇAĞRILDI ---
            // Kod tekrarı olan profil oluşturma mantığı buradaydı, artık fonksiyonda.
            await _createOrUpdateProfileData(tx, userId, input);
            // --- DEĞİŞİKLİK SONU ---


            // 7. Sosyal Bağlantıyı (ExternalLogin) Oluştur
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

            // 8. JWT Oluştur
            const tokens = await signTokens(userId, true);

            // 9. Refresh Token'ı Kaydet
            const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
            const expiresAt = new Date(Date.now() + (env.JWT_REFRESH_EXPIRATION_DAYS * 24 * 60 * 60 * 1000));

            await tx.refreshToken.deleteMany({ where: { userId, deviceId } });
            await tx.refreshToken.create({
                data: {
                    userId: userId,
                    tokenHash: refreshTokenHash,
                    expiresAt: expiresAt,
                    createdByIP: ipAddress,
                    userAgent: userAgent,
                    deviceId: deviceId
                }
            });

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
        logger.error(error, 'Sosyal Kayıt Transaction Hatası');
        throw new Error('Internal Server Error');
    }
};

// === SOCIAL LOGIN SERVİSİ ===
export const socialLoginService = async (
    input: SocialLoginInput['body'],
    ipAddress: string,
    userAgent: string,
    deviceId: string
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

    if (user.isEmailVerified && user.UserLocalCredential &&
        !user.UserExternalLogin.some((l: UserExternalLogin) => l.loginProvider === input.provider)) {
        throw new Error('ACCOUNT_MERGE_REQUIRED');
    }

    logger.info(`Sosyal kullanıcı giriş yaptı: ${user.userId}, Doğrulanmış: ${user.isEmailVerified}`);

    const tokens = await signTokens(user.userId, true);
    const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
    const expiresAt = new Date(Date.now() + (env.JWT_REFRESH_EXPIRATION_DAYS * 24 * 60 * 60 * 1000));

    await prisma.$transaction(async (tx) => {
        await tx.refreshToken.deleteMany({ where: { userId: user.userId, deviceId } });
        await tx.refreshToken.create({
            data: {
                userId: user.userId,
                tokenHash: refreshTokenHash,
                expiresAt: expiresAt,
                createdByIP: ipAddress,
                userAgent: userAgent,
                deviceId: deviceId
            }
        });

        if (!user.isEmailVerified) {
            await tx.user.update({
                where: { userId: user.userId },
                data: { isEmailVerified: true }
            });
        }

        if (!user.UserExternalLogin.some((l: UserExternalLogin) => l.loginProvider === input.provider)) {
            await tx.userExternalLogin.create({
                data: {
                    userId: user.userId,
                    loginProvider: input.provider,
                    providerKey: providerData.externalId,
                }
            });
        }
    });

    return tokens;
};

// === YENİ SOCIAL MERGE SERVİSİ ===
export const socialMergeService = async (
    input: SocialMergeInput['body'],
    ipAddress: string,
    userAgent: string,
    deviceId: string
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
        include: { UserLocalCredential: true }
    });

    if (!user || !user.UserLocalCredential) {
        throw new Error('INVALID_CREDENTIALS');
    }

    const passwordMatch = await bcrypt.compare(
        input.password,
        user.UserLocalCredential.passwordHash
    );

    if (!passwordMatch) {
        throw new Error('INVALID_CREDENTIALS');
    }

    logger.info(`Hesap birleştiriliyor: ${user.userId} -> ${input.provider}`);

    const tokens = await signTokens(user.userId, true);
    const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
    const expiresAt = new Date(Date.now() + (env.JWT_REFRESH_EXPIRATION_DAYS * 24 * 60 * 60 * 1000));

    await prisma.$transaction(async (tx) => {
        await tx.refreshToken.deleteMany({ where: { userId: user.userId, deviceId } });
        await tx.refreshToken.create({
            data: {
                userId: user.userId,
                tokenHash: refreshTokenHash,
                expiresAt: expiresAt,
                createdByIP: ipAddress,
                userAgent: userAgent,
                deviceId: deviceId
            }
        });

        if (!user.isEmailVerified) {
            await tx.user.update({
                where: { userId: user.userId },
                data: { isEmailVerified: true }
            });
        }

        await tx.userExternalLogin.upsert({
            where: {
                loginProvider_providerKey: {
                    loginProvider: input.provider,
                    providerKey: providerData.externalId,
                }
            },
            create: {
                userId: user.userId,
                loginProvider: input.provider,
                providerKey: providerData.externalId,
            },
            update: {}
        });
    });

    return tokens;
};

// === YENİ REFRESH TOKEN SERVİSİ (BUG DÜZELTİLDİ) ===
export const refreshTokenService = async (
    refreshToken: string,
    deviceId: string,
    ipAddress: string,
    userAgent: string
) => {

    // 1. JWT_SECRET'in varlığını kontrol et (artık env.ts'den geliyor)
    const JWT_SECRET = env.JWT_SECRET;

    // 2. Gelen Refresh Token'ı doğrula
    let payload: { sub: string };
    try {
        payload = jwt.verify(refreshToken, JWT_SECRET) as { sub: string };
    } catch (error) {
        logger.warn(error, 'Geçersiz refresh token (verify hatası)');
        throw new Error('INVALID_REFRESH_TOKEN');
    }

    const userId = payload.sub;

    // 3. Token'ı Veritabanında Ara
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

    // 4. Gelen Token, Veritabanındaki Hash ile Eşleşiyor mu?
    const tokenMatch = await bcrypt.compare(refreshToken, tokenRecord.tokenHash);
    if (!tokenMatch) {
        throw new Error('INVALID_REFRESH_TOKEN');
    }

    // 5. BAŞARILI: Refresh Token geçerli.
    logger.info(`Token yenileniyor: ${userId}, Cihaz: ${deviceId}`);

    const user = await prisma.user.findUnique({
        where: { userId },
        select: { isEmailVerified: true }
    });
    if (!user) {
        throw new Error('INVALID_REFRESH_TOKEN');
    }

    // 6. Yeni token setini oluştur
    const newTokens = await signTokens(userId, user.isEmailVerified);
    const newRefreshTokenHash = await bcrypt.hash(newTokens.refreshToken, 10);
    const newExpiresAt = new Date(Date.now() + (env.JWT_REFRESH_EXPIRATION_DAYS * 24 * 60 * 60 * 1000));

    // 7. Atomik İşlem: ESKİ token'ı SİL, YENİ token'ı EKLE
    await prisma.$transaction(async (tx) => {
        // 1. Bu cihaza ait mevcut token'ları sil (veya 'isUsed' yap)
        // 'deleteMany' kullanmak '@@unique' kuralı için daha güvenlidir.
        await tx.refreshToken.deleteMany({
            where: {
                userId: userId,
                deviceId: deviceId,
            },
        });

        // 2. Yeni refresh token'ı kaydet
        await tx.refreshToken.create({
            data: {
                userId: userId,
                tokenHash: newRefreshTokenHash,
                expiresAt: newExpiresAt,
                createdByIP: ipAddress,
                userAgent: userAgent,
                deviceId: deviceId
            }
        });
    });

    // 8. Yeni token setini döndür
    return newTokens;
};

// === YENİ LOGOUT SERVİSİ ===
export const logoutUserService = async (userId: string, deviceId: string) => {
    await prisma.refreshToken.deleteMany({
        where: {
            userId: userId,
            deviceId: deviceId // Sadece bu cihazı sil
        },
    });

    logger.info(`Kullanıcı çıkış yaptı (cihaz: ${deviceId}): ${userId}`);
    return;
};