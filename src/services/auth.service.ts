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
    SocialMergeInput
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
    UserExternalLogin // 'l' parametresinin tipini belirlemek için import ettik
} from '@prisma/client';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

// Referans için interface (artık explicit olarak kullanılmıyor)
interface RegisterResult {
    user: {
        id: string;
        email: string;
    };
    tokens: {
        accessToken: string;
        refreshToken: string;
    };
}

// === REGISTER USER SERVICE ===
export const registerUserService = async (
    input: RegisterInput['body'],
    ipAddress: string,
    userAgent: string,
    deviceId: string // <-- EKLENDİ
) => {

    // 1. Şifreyi Hash'le
    const passwordHash = await bcrypt.hash(input.password, 12);

    // 2. "Akıllı Kayıt" için e-posta/kullanıcı adını kontrol et
    const existingUser = await prisma.user.findFirst({
        where: {
            OR: [{ email: input.email }, { username: input.username }],
        },
    });

    // 3. Durum 1: "Doğrulanmış" Çakışma
    if (existingUser && existingUser.isEmailVerified) {
        throw new Error('CONFLICT');
    }

    // --- Buradan sonrası Atomik (Transaction) olmalı ---
    try {
        const { user, tokens } = await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
            let userId: string;

            // 4. Durum 2: "İşgal (Overwrite)"
            if (existingUser && !existingUser.isEmailVerified) {
                console.log(`Akıllı Kayıt: ${existingUser.userId} ID'li doğrulanmamış hesap üzerine yazılıyor...`);
                userId = existingUser.userId;

                // 4a. ESKİ SAHTE profil verilerini SİL
                await tx.userHealthLimitation.deleteMany({ where: { userId } });
                await tx.userGoalPart.deleteMany({ where: { userId } });
                await tx.userAvailableWorkoutEquipment.deleteMany({ where: { userId } });
                await tx.userWorkoutLocation.deleteMany({ where: { userId } });
                try { await tx.userProfile.delete({ where: { userId } }); } catch (e) { }
                try { await tx.userBody.delete({ where: { userId } }); } catch (e) { }
                try { await tx.userGoal.delete({ where: { userId } }); } catch (e) { }
                try { await tx.userSetting.delete({ where: { userId } }); } catch (e) { }

                // 4b. Ana User ve Şifresini GÜNCELLE
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
                // 5. Durum 3: "Temiz Kayıt" (UUID Düzeltmesi uygulandı)
                console.log(`Temiz Kayıt: ${input.email} için yeni kullanıcı oluşturuluyor...`);

                // === DÜZELTME BAŞLANGICI (UUID Çakışması) ===
                // Adım 5a: ÖNCE User'ı oluştur (ID'yi veritabanı oluşturur)
                const newUser = await tx.user.create({
                    data: {
                        email: input.email,
                        username: input.username,
                        isEmailVerified: false,
                        // UserLocalCredential BLOKUNU BURADAN KALDIRDIK
                    },
                    select: { userId: true },
                });
                userId = newUser.userId;

                // Adım 5b: ŞİMDİ UserLocalCredential'ı oluştur
                await tx.userLocalCredential.create({
                    data: {
                        userId: userId,
                        passwordHash,
                    },
                });
                // === DÜZELTME SONU ===
            }

            // 6. YENİ ve GERÇEK profil verilerini oluştur
            await tx.userProfile.create({ data: { userId, ...input.profile } });
            await tx.userBody.create({ data: { userId, ...input.body } });
            await tx.userGoal.create({ data: { userId, ...input.goal } });
            await tx.userSetting.create({ data: { userId, ...input.settings } });
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

            // 7. Doğrulama Kodu Oluştur ve Kaydet (Zorunlu IP/Agent ile)
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

            // 10. Refresh Token'ı Kaydet (Zorunlu IP/Agent ile)
            const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
            const expiresAtRT = new Date(Date.now() + (parseInt(process.env.JWT_REFRESH_EXPIRATION_DAYS || '30') * 24 * 60 * 60 * 1000));

            // --- DEĞİŞİKLİK ---
            await tx.refreshToken.deleteMany({ where: { userId, deviceId } });
            await tx.refreshToken.create({
                data: {
                    userId: userId,
                    tokenHash: refreshTokenHash,
                    expiresAt: expiresAtRT,
                    createdByIP: ipAddress,
                    userAgent: userAgent,
                    deviceId: deviceId // <-- EKLENDİ
                }
            });
            // --- DEĞİŞİKLİK SONU ---

            return { user: { id: userId, email: input.email }, tokens };
        });

        return { user, tokens };

    } catch (error: unknown) {
        if (error instanceof PrismaClientKnownRequestError) {
            if (error.code === 'P2002') {
                throw new Error('CONFLICT');
            }
        }
        console.error('Kayıt Transaction Hatası:', error);
        throw new Error('Internal Server Error');
    }
};

// === LOGIN SERVİSİ ===
export const loginUserService = async (
    input: LoginInput['body'],
    ipAddress: string,
    userAgent: string,
    deviceId: string // <-- EKLENDİ
) => {
    const { loginIdentifier, password } = input;

    // 1. Kullanıcıyı bul
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

    // 2. Kontroller
    if (!user) {
        throw new Error('INVALID_CREDENTIALS');
    }
    if (!user.UserLocalCredential) {
        throw new Error('INVALID_CREDENTIALS');
    }
    const passwordMatch = await bcrypt.compare(
        password,
        user.UserLocalCredential.passwordHash
    );
    if (!passwordMatch) {
        throw new Error('INVALID_CREDENTIALS');
    }

    // 5. BAŞARILI
    console.log(`Kullanıcı giriş yaptı: ${user.userId}, Doğrulanmış: ${user.isEmailVerified}`);
    const tokens = await signTokens(user.userId, user.isEmailVerified);

    // 6. Refresh Token'ı Kaydet
    const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
    const expiresAt = new Date(Date.now() + (parseInt(process.env.JWT_REFRESH_EXPIRATION_DAYS || '30') * 24 * 60 * 60 * 1000));

    // --- DEĞİŞİKLİK ---
    await prisma.$transaction([
        prisma.refreshToken.deleteMany({ where: { userId: user.userId, deviceId } }),
        prisma.refreshToken.create({
            data: {
                userId: user.userId,
                tokenHash: refreshTokenHash,
                expiresAt: expiresAt,
                createdByIP: ipAddress,
                userAgent: userAgent,
                deviceId: deviceId // <-- EKLENDİ
            }
        })
    ]);
    // --- DEĞİŞİKLİK SONU ---

    return tokens;
};

// === VERIFY EMAIL CODE SERVİSİ ===
export const verifyEmailCodeService = async (
    userId: string,
    code: string,
    ipAddress: string,
    userAgent: string,
    deviceId: string // <-- EKLENDİ
) => {
    // 1. Kullanıcıyı ve token'ı bul
    const userWithToken = await prisma.user.findUnique({
        where: { userId },
        include: {
            EmailVerificationToken: {
                where: { isUsed: false },
            },
        },
    });

    // 2. Kontroller
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

    // 5. BAŞARILI
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

    // 6. YENİ JWT'leri oluştur
    console.log(`Kullanıcı doğrulandı: ${userId}`);
    const tokens = await signTokens(userId, true);

    // 7. Yeni Refresh Token'ı Kaydet
    const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
    const expiresAt = new Date(Date.now() + (parseInt(process.env.JWT_REFRESH_EXPIRATION_DAYS || '30') * 24 * 60 * 60 * 1000));

    // --- DEĞİŞİKLİK ---
    await prisma.$transaction([
        prisma.refreshToken.deleteMany({ where: { userId: userId, deviceId } }),
        prisma.refreshToken.create({
            data: {
                userId: userId,
                tokenHash: refreshTokenHash,
                expiresAt: expiresAt,
                createdByIP: ipAddress,
                userAgent: userAgent,
                deviceId: deviceId // <-- EKLENDİ
            }
        })
    ]);
    // --- DEĞİŞİKLİK SONU ---

    return tokens;
};

// === RESEND VERIFICATION CODE SERVİSİ ===
export const resendVerificationCodeService = async (
    userId: string,
    ipAddress: string,
    userAgent: string
) => {
    // 1. Kullanıcıyı bul
    const user = await prisma.user.findUnique({
        where: { userId },
        select: { email: true, isEmailVerified: true },
    });

    // 2. Kontroller
    if (!user) {
        throw new Error('User not found');
    }
    if (user.isEmailVerified) {
        throw new Error('ALREADY_VERIFIED');
    }

    // 4. BAŞARILI
    const code = generateSixDigitCode();
    const hashedCode = await bcrypt.hash(code, 10);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    // 5. Atomik İşlem
    try {
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
    } catch (txError) {
        console.error("Resend Code Transaction Hatası:", txError);
        throw new Error("Veritabanı işlemi başarısız oldu.");
    }

    // 6. E-postayı GÖNDER
    try {
        await sendVerificationCode(user.email, code);
    } catch (emailError) {
        console.error("Resend Code - E-posta Gönderim Hatası:", emailError);
        throw new Error('E-posta gönderilemedi.');
    }
    return;
};

// === FORGOT PASSWORD SERVİSİ ===
export const forgotPasswordService = async (
    email: string,
    ipAddress: string,
    userAgent: string
) => {
    // 1. Kullanıcıyı bul
    const user = await prisma.user.findUnique({
        where: { email },
    });

    // 2. GÜVENLİK KURALI
    if (!user || !user.isEmailVerified) {
        console.log(`[Forgot PWD]: Sessiz çıkış (Kullanıcı bulunamadı veya doğrulanmamış): ${email}`);
        return;
    }

    // 3. BAŞARILI
    const code = generateSixDigitCode();
    const hashedCode = await bcrypt.hash(code, 10);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 dakika

    // 4. Atomik İşlem
    try {
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
    } catch (txError) {
        console.error("Forgot PWD Transaction Hatası:", txError);
        throw new Error('Veritabanı işlemi başarısız oldu.');
    }

    // 5. E-postayı GÖNDER
    try {
        await sendPasswordResetCode(user.email, code);
    } catch (emailError) {
        console.error("Forgot PWD - E-posta Gönderim Hatası:", emailError);
        throw new Error('E-posta gönderilemedi.');
    }
    return;
};

// === RESET PASSWORD SERVİSİ ===
export const resetPasswordService = async (input: ResetPasswordInput['body']) => {
    const { email, code, newPassword } = input;

    // 1. Kullanıcıyı ve geçerli token'ı bul
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

    // 2. Kontroller
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

    // 6. Yeni şifreyi hash'le
    const newPasswordHash = await bcrypt.hash(newPassword, 12);

    // 7. Atomik İşlem
    try {
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
    } catch (txError) {
        console.error("Reset PWD Transaction Hatası:", txError);
        throw new Error('Veritabanı işlemi başarısız oldu.');
    }

    console.log(`Kullanıcı şifresi sıfırlandı: ${userWithToken.userId}`);
    return;
};

// === SOCIAL REGISTER SERVİSİ ===
export const socialRegisterService = async (
    input: SocialRegisterInput['body'],
    ipAddress: string,
    userAgent: string,
    deviceId: string // <-- EKLENDİ
) => {

    // 1. Gelen Token'ı Doğrula
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

    // 2. E-postayı veritabanında ara
    const existingUser = await prisma.user.findUnique({
        where: { email: providerData.email },
        include: { UserLocalCredential: true },
    });

    // 3. Durum 1: "Çakışma"
    if (existingUser && existingUser.isEmailVerified && existingUser.UserLocalCredential) {
        throw new Error('CONFLICT');
    }

    // --- Buradan sonrası Atomik (Transaction) olmalı ---
    try {
        const tokens = await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
            let userId: string;

            // 4. Durum 2: "Dolaylı Doğrulama / Overwrite"
            if (existingUser && !existingUser.isEmailVerified) {
                console.log(`Sosyal Kayıt (Overwrite): ${existingUser.userId} ID'li doğrulanmamış hesap üzerine yazılıyor...`);
                userId = existingUser.userId;

                // 4a. ESKİ SAHTE profil verilerini SİL
                await tx.userHealthLimitation.deleteMany({ where: { userId } });
                await tx.userGoalPart.deleteMany({ where: { userId } });
                await tx.userAvailableWorkoutEquipment.deleteMany({ where: { userId } });
                await tx.userWorkoutLocation.deleteMany({ where: { userId } });
                try { await tx.userProfile.delete({ where: { userId } }); } catch (e) { }
                try { await tx.userBody.delete({ where: { userId } }); } catch (e) { }
                try { await tx.userGoal.delete({ where: { userId } }); } catch (e) { }
                try { await tx.userSetting.delete({ where: { userId } }); } catch (e) { }

                // 4b. Ana User'ı GÜNCELLE
                await tx.user.update({
                    where: { userId },
                    data: {
                        isEmailVerified: true,
                        createdAt: new Date(),
                    },
                });

            } else {
                // 5. Durum 3: "Temiz Kayıt" (UUID Düzeltmesi uygulandı)
                console.log(`Sosyal Kayıt (Temiz): ${providerData.email} için yeni kullanıcı oluşturuluyor...`);

                // Adım 5a: ÖNCE User'ı oluştur
                const newUser = await tx.user.create({
                    data: {
                        email: providerData.email,
                        username: input.username,
                        isEmailVerified: true,
                    },
                    select: { userId: true },
                });
                userId = newUser.userId;
                // Adım 5b: Sosyal kayıtta UserLocalCredential OLUŞTURULMAZ
            }

            // 6. YENİ ve GERÇEK profil verilerini oluştur
            await tx.userProfile.create({ data: { userId, ...input.profile } });
            await tx.userBody.create({ data: { userId, ...input.body } });
            await tx.userGoal.create({ data: { userId, ...input.goal } });
            await tx.userSetting.create({ data: { userId, ...input.settings } });

            // 6b. M:N Veriler
            await tx.userGoalPart.createMany({
                data: input.targetBodyPartIds.map((id) => ({ userId, goalBodyPartId: id })),
            });
            await tx.userAvailableWorkoutEquipment.createMany({
                data: input.availableEquipmentIds.map((id) => ({ userId, workoutEquipmentId: id })),
            });
            await tx.userWorkoutLocation.createMany({
                data: input.workoutLocationIds.map((id) => ({ userId, workoutLocationId: id })),
            });
            if (input.healthLimitationIds.length > 0) {
                await tx.userHealthLimitation.createMany({
                    data: input.healthLimitationIds.map((id) => ({ userId, healthLimitationId: id })),
                });
            }

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
            const expiresAt = new Date(Date.now() + (parseInt(process.env.JWT_REFRESH_EXPIRATION_DAYS || '30') * 24 * 60 * 60 * 1000));

            // --- DEĞİŞİKLİK ---
            await tx.refreshToken.deleteMany({ where: { userId, deviceId } });
            await tx.refreshToken.create({
                data: {
                    userId: userId,
                    tokenHash: refreshTokenHash,
                    expiresAt: expiresAt,
                    createdByIP: ipAddress,
                    userAgent: userAgent,
                    deviceId: deviceId // <-- EKLENDİ
                }
            });
            // --- DEĞİŞİKLİK SONU ---

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
        console.error('Sosyal Kayıt Transaction Hatası:', error);
        throw new Error('Internal Server Error');
    }
};

// === SOCIAL LOGIN SERVİSİ ===
export const socialLoginService = async (
    input: SocialLoginInput['body'],
    ipAddress: string,
    userAgent: string,
    deviceId: string // <-- EKLENDİ
) => {

    // 1. Gelen Token'ı Doğrula
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

    // 2. Kullanıcıyı bul (Provider ID ile)
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
            UserExternalLogin: true, // Hata düzeltmesi eklendi
        },
    });

    // 3. Durum 1: Bulunamadı -> E-posta ile ara
    if (!user) {
        const userByEmail = await prisma.user.findUnique({
            where: { email: providerData.email },
            include: {
                UserLocalCredential: true,
                UserExternalLogin: true, // Hata düzeltmesi eklendi
            },
        });

        if (!userByEmail) {
            throw new Error('USER_NOT_FOUND');
        }
        user = userByEmail;
    }

    // 4. Durum 2: "Hesap Birleştirme Gerekli"
    if (user.isEmailVerified && user.UserLocalCredential &&
        !user.UserExternalLogin.some((l: UserExternalLogin) => l.loginProvider === input.provider)) { // l: any hatası düzeltildi
        throw new Error('ACCOUNT_MERGE_REQUIRED');
    }

    // 5. Durum 3: "Dolaylı Birleştirme / Giriş"
    console.log(`Sosyal kullanıcı giriş yaptı: ${user.userId}, Doğrulanmış: ${user.isEmailVerified}`);

    // 6. Atomik İşlem
    const tokens = await signTokens(user.userId, true);
    const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
    const expiresAt = new Date(Date.now() + (parseInt(process.env.JWT_REFRESH_EXPIRATION_DAYS || '30') * 24 * 60 * 60 * 1000));

    await prisma.$transaction(async (tx) => {
        // --- DEĞİŞİKLİK ---
        await tx.refreshToken.deleteMany({ where: { userId: user.userId, deviceId } });
        await tx.refreshToken.create({
            data: {
                userId: user.userId,
                tokenHash: refreshTokenHash,
                expiresAt: expiresAt,
                createdByIP: ipAddress,
                userAgent: userAgent,
                deviceId: deviceId // <-- EKLENDİ
            }
        });
        // --- DEĞİŞİKLİK SONU ---

        // Dolaylı doğrulama
        if (!user.isEmailVerified) {
            await tx.user.update({
                where: { userId: user.userId },
                data: { isEmailVerified: true }
            });
        }

        // Dolaylı birleştirme
        if (!user.UserExternalLogin.some((l: UserExternalLogin) => l.loginProvider === input.provider)) { // l: any hatası düzeltildi
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
    deviceId: string // <-- EKLENDİ
) => {

    // 1. Sosyal Token'ı Doğrula (Google vb.)
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

    // 2. Kullanıcıyı e-posta ile bul (ŞİFRESİNİ ALARAK)
    const user = await prisma.user.findUnique({
        where: { email: providerData.email },
        include: { UserLocalCredential: true }
    });

    // 3. Kontrol 1: Kullanıcı bulunamadı VEYA şifresi yok
    if (!user || !user.UserLocalCredential) {
        throw new Error('INVALID_CREDENTIALS');
    }

    // 4. Kontrol 2: Şifre Eşleşiyor mu?
    const passwordMatch = await bcrypt.compare(
        input.password,
        user.UserLocalCredential.passwordHash
    );

    if (!passwordMatch) {
        throw new Error('INVALID_CREDENTIALS');
    }

    // 5. BAŞARILI: Hem sosyal token hem de şifre doğru.
    console.log(`Hesap birleştiriliyor: ${user.userId} -> ${input.provider}`);

    // 6. Atomik İşlem: Token'ları kaydet, kullanıcıyı doğrula, hesabı bağla
    const tokens = await signTokens(user.userId, true);
    const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
    const expiresAt = new Date(Date.now() + (parseInt(process.env.JWT_REFRESH_EXPIRATION_DAYS || '30') * 24 * 60 * 60 * 1000));

    await prisma.$transaction(async (tx) => {
        // --- DEĞİŞİKLİK ---
        await tx.refreshToken.deleteMany({ where: { userId: user.userId, deviceId } });
        await tx.refreshToken.create({
            data: {
                userId: user.userId,
                tokenHash: refreshTokenHash,
                expiresAt: expiresAt,
                createdByIP: ipAddress,
                userAgent: userAgent,
                deviceId: deviceId // <-- EKLENDİ
            }
        });
        // --- DEĞİŞİKLİK SONU ---

        // 6b. Kullanıcıyı doğrulanmış yap
        if (!user.isEmailVerified) {
            await tx.user.update({
                where: { userId: user.userId },
                data: { isEmailVerified: true }
            });
        }

        // 6c. Sosyal bağlantıyı ekle
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

    // 7. Yeni, "doğrulanmış" token'ları döndür
    return tokens;
};

// === YENİ REFRESH TOKEN SERVİSİ ===
export const refreshTokenService = async (
    refreshToken: string,
    deviceId: string, // <-- EKLENDİ
    ipAddress: string,
    userAgent: string
) => {
    // 1. JWT_SECRET'in varlığını kontrol et
    const JWT_SECRET = process.env.JWT_SECRET;
    if (!JWT_SECRET) {
        throw new Error('JWT_SECRET tanımlanmamış.');
    }

    // 2. Gelen Refresh Token'ı doğrula (Süre ve İmza)
    let payload: { sub: string };
    try {
        payload = jwt.verify(refreshToken, JWT_SECRET) as { sub: string };
    } catch (error) {
        // Token süresi dolmuş veya imzası geçersiz
        throw new Error('INVALID_REFRESH_TOKEN');
    }

    const userId = payload.sub;

    // 3. Token'ı Veritabanında Ara
    // --- DEĞİŞİKLİK ---
    const tokenRecord = await prisma.refreshToken.findFirst({
        where: {
            userId: userId,
            deviceId: deviceId, // <-- EKLENDİ
            isUsed: false,
            expiresAt: { gt: new Date() }, // Süresi dolmamış
        },
    });
    // --- DEĞİŞİKLİK SONU ---

    if (!tokenRecord) {
        throw new Error('INVALID_REFRESH_TOKEN');
    }

    // 4. Gelen Token, Veritabanındaki Hash ile Eşleşiyor mu?
    const tokenMatch = await bcrypt.compare(refreshToken, tokenRecord.tokenHash);
    if (!tokenMatch) {
        // Bu, çalınmış bir token'ın yeniden kullanılma girişimi olabilir
        throw new Error('INVALID_REFRESH_TOKEN');
    }

    // 5. BAŞARILI: Refresh Token geçerli.
    // Güvenlik için "Token Rotation" (Token Döndürme) uyguluyoruz.
    // Yeni bir Access Token VE YENİ BİR REFRESH TOKEN oluşturacağız.

    console.log(`Token yenileniyor: ${userId}`);

    // Kullanıcının 'isEmailVerified' durumunu al
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
    const newExpiresAt = new Date(Date.now() + (parseInt(process.env.JWT_REFRESH_EXPIRATION_DAYS || '30') * 24 * 60 * 60 * 1000));

    // 7. Atomik İşlem: ESKİ token'ı SİL, YENİ token'ı EKLE
    await prisma.$transaction(async (tx) => {
        // Güvenlik için tüm tokenları silebiliriz veya sadece kullanılanı:
        // Biz sadece bu spesifik token'ı silmeyi (veya 'isUsed' yapmayı) seçiyoruz
        await tx.refreshToken.update({
            where: { refreshTokenId: tokenRecord.refreshTokenId },
            data: { isUsed: true }, // Veya delete()
        });

        // Yeni refresh token'ı kaydet
        // --- DEĞİŞİKLİK ---
        await tx.refreshToken.create({
            data: {
                userId: userId,
                tokenHash: newRefreshTokenHash,
                expiresAt: newExpiresAt,
                createdByIP: ipAddress,
                userAgent: userAgent,
                deviceId: deviceId // <-- EKLENDİ
            }
        });
        // --- DEĞİŞİKLİK SONU ---
    });

    // 8. Yeni token setini döndür
    return newTokens;
};

// === YENİ LOGOUT SERVİSİ ===
export const logoutUserService = async (userId: string, deviceId: string) => { // <-- İMZA DEĞİŞTİ
    // Plan: Kullanıcının sadece bu cihaza ait refresh token'ını sil.
    // --- İÇERİK DEĞİŞTİ ---
    await prisma.refreshToken.deleteMany({
        where: {
            userId: userId,
            deviceId: deviceId // <-- Sadece bu cihazı sil
        },
    });

    console.log(`Kullanıcı çıkış yaptı (cihaz: ${deviceId}): ${userId}`);
    return;
};