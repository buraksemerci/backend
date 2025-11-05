// Dosya: src/services/profile.service.ts
import prisma from '../utils/prisma';
import logger from '../utils/logger';

/**
 * Fetches all profile data for the logged-in user.
 * (Base User info, 1:1 Profile, Body, Goal, Settings, and M:N relations)
 * @param {string} userId - The user ID from the JWT
 */
export const getMyProfileService = async (userId: string) => {

    // --- Step 1: Get the user's preferred language ---
    const FALLBACK_LANG = 'en'; // Son çare dil 'en'
    let languageCode = 'tr'; // Varsayılan dil 'tr'

    try {
        const settings = await prisma.userSetting.findUnique({
            where: { userId },
            select: { preferredLanguage: true },
        });
        if (settings?.preferredLanguage) {
            languageCode = settings.preferredLanguage;
        }
    } catch (e) {
        logger.warn(e, `Could not find language setting for user ${userId}, defaulting to 'tr'.`);
    }

    // --- YENİ: Denenecek dillerin listesi ---
    const languagesToTry = [...new Set([languageCode, FALLBACK_LANG])];
    // Not: 'tr' zaten languageCode'un varsayılanı, o yüzden tekrar eklemeye gerek yok.
    // Eğer varsayılan 'tr' olmasaydı: [...new Set([languageCode, 'tr', FALLBACK_LANG])]

    // --- Step 2: Fetch all data based on the user's language (GÜNCELLENDİ) ---
    const userProfile = await prisma.user.findUnique({
        where: { userId },
        select: {
            // Base User data
            userId: true,
            email: true,
            username: true,
            isEmailVerified: true,
            createdAt: true,

            // 1:1 Related data
            Profile: true,
            Body: true,
            Goal: true,
            Setting: true,

            // --- Step 3: M:N Related data (GÜNCELLENDİ) ---
            HealthLimitations: {
                select: {
                    HealthLimitation: {
                        select: {
                            healthLimitationId: true,
                            // DİLLERİ FİLTRELE
                            translations: {
                                where: { languageCode: { in: languagesToTry } },
                                select: { name: true, description: true, languageCode: true } // languageCode'u al
                            }
                        },
                    },
                },
            },
            TargetBodyParts: {
                select: {
                    GoalBodyPart: {
                        select: {
                            goalBodyPartId: true,
                            translations: {
                                where: { languageCode: { in: languagesToTry } },
                                select: { name: true, description: true, languageCode: true }
                            }
                        },
                    },
                },
            },
            AvailableEquipment: {
                select: {
                    WorkoutEquipment: {
                        select: {
                            workoutEquipmentId: true,
                            translations: {
                                where: { languageCode: { in: languagesToTry } },
                                select: { name: true, description: true, languageCode: true }
                            }
                        },
                    },
                },
            },
            WorkoutLocations: {
                select: {
                    WorkoutLocation: {
                        select: {
                            workoutLocationId: true,
                            translations: {
                                where: { languageCode: { in: languagesToTry } },
                                select: { name: true, description: true, languageCode: true }
                            }
                        },
                    },
                },
            },
        },
    });

    if (!userProfile) {
        throw new Error('USER_NOT_FOUND');
    }

    // --- Step 4: Clean up the data (GÜNCELLENDİ - DİL ÖNCELİKLENDİRME) ---
    const formattedProfile = {
        ...userProfile,
        HealthLimitations: userProfile.HealthLimitations.map(item => {
            const t = item.HealthLimitation.translations.find(tr => tr.languageCode === languageCode) ||
                item.HealthLimitation.translations.find(tr => tr.languageCode === FALLBACK_LANG);
            return {
                id: item.HealthLimitation.healthLimitationId,
                name: t?.name || 'N/A',
                description: t?.description || null,
            };
        }),
        TargetBodyParts: userProfile.TargetBodyParts.map(item => {
            const t = item.GoalBodyPart.translations.find(tr => tr.languageCode === languageCode) ||
                item.GoalBodyPart.translations.find(tr => tr.languageCode === FALLBACK_LANG);
            return {
                id: item.GoalBodyPart.goalBodyPartId,
                name: t?.name || 'N/A',
                description: t?.description || null,
            };
        }),
        AvailableEquipment: userProfile.AvailableEquipment.map(item => {
            const t = item.WorkoutEquipment.translations.find(tr => tr.languageCode === languageCode) ||
                item.WorkoutEquipment.translations.find(tr => tr.languageCode === FALLBACK_LANG);
            return {
                id: item.WorkoutEquipment.workoutEquipmentId,
                name: t?.name || 'N/A',
                description: t?.description || null,
            };
        }),
        WorkoutLocations: userProfile.WorkoutLocations.map(item => {
            const t = item.WorkoutLocation.translations.find(tr => tr.languageCode === languageCode) ||
                item.WorkoutLocation.translations.find(tr => tr.languageCode === FALLBACK_LANG);
            return {
                id: item.WorkoutLocation.workoutLocationId,
                name: t?.name || 'N/A',
                description: t?.description || null,
            };
        }),
    };

    return formattedProfile;
};