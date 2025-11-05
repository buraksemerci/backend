// Dosya: src/services/auth.service.ts
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
import logger from '../utils/logger';
import { env } from '../utils/env';


async function _createOrUpdateProfileData(
    tx: Prisma.TransactionClient,
    userId: string,
    input: ProfileCreationInput
) {
    logger.info(`Creating/Updating profile data for user ${userId}...`);

    // 1. Clear all previous data (for Overwrite/Takeover scenario)
    // (deleteMany won't throw an error if record doesn't exist, delete will)
    await tx.userHealthLimitation.deleteMany({ where: { userId } });
    await tx.userGoalPart.deleteMany({ where: { userId } });
    await tx.userAvailableWorkoutEquipment.deleteMany({ where: { userId } });
    await tx.userWorkoutLocation.deleteMany({ where: { userId } });
    await tx.userProfile.deleteMany({ where: { userId } });
    await tx.userBody.deleteMany({ where: { userId } });
    await tx.userGoal.deleteMany({ where: { userId } });
    await tx.userSetting.deleteMany({ where: { userId } });

    // 2. Create new 1:1 data
    await tx.userProfile.create({ data: { userId, ...input.profile } });
    await tx.userBody.create({ data: { userId, ...input.body } });
    await tx.userGoal.create({ data: { userId, ...input.goal } });
    await tx.userSetting.create({ data: { userId, ...input.settings } });

    // 3. Create new M:N data
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
    logger.info(`Profile data created successfully for user ${userId}.`);
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
                logger.info(`Smart Registration: Overwriting unverified user ${existingUser.userId}...`);
                userId = existingUser.userId;

                // Update main User and Password
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
                logger.info(`Clean Registration: Creating new user for ${input.email}...`);

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

            // --- CHANGE: HELPER FUNCTION CALLED ---
            await _createOrUpdateProfileData(tx, userId, input);
            // --- END CHANGE ---

            // 7. Verification Code
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

            // 8. Send Email
            await sendVerificationCode(input.email, code);

            // 9. Create JWT
            const tokens = await signTokens(userId, false);

            // 10. Save Refresh Token
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
        logger.error(error, 'Registration Transaction Error');
        throw new Error('Internal Server Error');
    }
};

// === LOGIN SERVICE ===
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
        // This is likely a social-only user, no local password
        throw new Error('INVALID_CREDENTIALS');
    }
    const passwordMatch = await bcrypt.compare(
        password,
        user.UserLocalCredential.passwordHash
    );
    if (!passwordMatch) {
        throw new Error('INVALID_CREDENTIALS');
    }

    logger.info(`User logged in: ${user.userId}, Verified: ${user.isEmailVerified}`);
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

// === VERIFY EMAIL CODE SERVICE ===
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

    logger.info(`User verified: ${userId}`);
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

// === RESEND VERIFICATION CODE SERVICE ===
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
        throw new Error('User not found'); // This will go to the global handler
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

// === FORGOT PASSWORD SERVICE ===
export const forgotPasswordService = async (
    email: string,
    ipAddress: string,
    userAgent: string
) => {
    const user = await prisma.user.findUnique({
        where: { email },
    });

    if (!user || !user.isEmailVerified) {
        logger.warn(`[Forgot PWD]: Silent exit (User not found or unverified): ${email}`);
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

// === RESET PASSWORD SERVICE ===
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

    logger.info(`User password reset: ${userWithToken.userId}`);
    return;
};

// === SOCIAL REGISTER SERVICE ===
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
        // TODO: Add Apple and Facebook verification here
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
                logger.info(`Social Registration (Overwrite): Overwriting unverified user ${existingUser.userId}...`);
                userId = existingUser.userId;

                await tx.user.update({
                    where: { userId },
                    data: {
                        isEmailVerified: true,
                        createdAt: new Date(),
                    },
                });

            } else {
                logger.info(`Social Registration (Clean): Creating new user for ${providerData.email}...`);

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

            // --- CHANGE: HELPER FUNCTION CALLED ---
            await _createOrUpdateProfileData(tx, userId, input);
            // --- END CHANGE ---


            // 7. Create Social Link (ExternalLogin)
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

            // 8. Create JWT
            const tokens = await signTokens(userId, true);

            // 9. Save Refresh Token
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
        logger.error(error, 'Social Registration Transaction Error');
        throw new Error('Internal Server Error');
    }
};

// === SOCIAL LOGIN SERVICE ===
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

    logger.info(`Social user logged in: ${user.userId}, Verified: ${user.isEmailVerified}`);

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

// === NEW SOCIAL MERGE SERVICE ===
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

    logger.info(`Merging account: ${user.userId} -> ${input.provider}`);

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

// === NEW REFRESH TOKEN SERVICE (BUG FIXED) ===
export const refreshTokenService = async (
    refreshToken: string,
    deviceId: string,
    ipAddress: string,
    userAgent: string
) => {

    const JWT_SECRET = env.JWT_SECRET;

    // 2. Verify incoming Refresh Token
    let payload: { sub: string };
    try {
        payload = jwt.verify(refreshToken, JWT_SECRET) as { sub: string };
    } catch (error) {
        logger.warn(error, 'Invalid refresh token (verify failed)');
        throw new Error('INVALID_REFRESH_TOKEN');
    }

    const userId = payload.sub;

    // 3. Find token in Database
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

    // 4. Does incoming token match the hash in the DB?
    const tokenMatch = await bcrypt.compare(refreshToken, tokenRecord.tokenHash);
    if (!tokenMatch) {
        throw new Error('INVALID_REFRESH_TOKEN');
    }

    // 5. SUCCESS: Refresh token is valid.
    logger.info(`Refreshing token for: ${userId}, Device: ${deviceId}`);

    const user = await prisma.user.findUnique({
        where: { userId },
        select: { isEmailVerified: true }
    });
    if (!user) {
        throw new Error('INVALID_REFRESH_TOKEN');
    }

    // 6. Create new token set
    const newTokens = await signTokens(userId, user.isEmailVerified);
    const newRefreshTokenHash = await bcrypt.hash(newTokens.refreshToken, 10);
    const newExpiresAt = new Date(Date.now() + (env.JWT_REFRESH_EXPIRATION_DAYS * 24 * 60 * 60 * 1000));

    // 7. Atomic Transaction: DELETE old token, ADD new token
    await prisma.$transaction(async (tx) => {
        // 1. Delete existing tokens for this device
        // Using 'deleteMany' is safer for the '@@unique' rule.
        await tx.refreshToken.deleteMany({
            where: {
                userId: userId,
                deviceId: deviceId,
            },
        });

        // 2. Save the new refresh token
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

    // 8. Return new token set
    return newTokens;
};

// === NEW LOGOUT SERVICE ===
export const logoutUserService = async (userId: string, deviceId: string) => {
    await prisma.refreshToken.deleteMany({
        where: {
            userId: userId,
            deviceId: deviceId // Only delete this device
        },
    });

    logger.info(`User logged out (device: ${deviceId}): ${userId}`);
    return;
};