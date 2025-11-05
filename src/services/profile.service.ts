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
    // (or default to 'tr')
    let languageCode = 'tr';
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

    // --- Step 2: Fetch all data based on the user's language ---
    const userProfile = await prisma.user.findUnique({
        where: { userId },
        select: {
            // Base User data
            userId: true,
            email: true,
            username: true,
            isEmailVerified: true,
            createdAt: true,

            // 1:1 Related data (These haven't changed)
            Profile: true, // UserProfile table
            Body: true,    // UserBody table
            Goal: true,    // UserGoal table
            Setting: true, // UserSetting table

            // --- Step 3: M:N Related data (REWRITTEN) ---
            // Now looks at '...Translation' table for 'name'
            HealthLimitations: {
                select: {
                    HealthLimitation: {
                        select: {
                            healthLimitationId: true,
                            // FILTER by language from the 'translations' relation
                            translations: {
                                where: { languageCode: languageCode },
                                select: { name: true, description: true }
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
                                where: { languageCode: languageCode },
                                select: { name: true, description: true }
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
                                where: { languageCode: languageCode },
                                select: { name: true, description: true }
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
                                where: { languageCode: languageCode },
                                select: { name: true, description: true }
                            }
                        },
                    },
                },
            },
        },
    });

    // 2. If user not found
    if (!userProfile) {
        throw new Error('USER_NOT_FOUND');
    }

    // --- Step 4: Clean up the data (flatten M:N data into a simple array) ---
    // (Now we need to fix the complex 'translations' array)
    const formattedProfile = {
        ...userProfile,
        // Corrected format: { id: 1, name: "Name in User's Language" }
        HealthLimitations: userProfile.HealthLimitations.map(item => ({
            id: item.HealthLimitation.healthLimitationId,
            name: item.HealthLimitation.translations[0]?.name || 'N/A',
            description: item.HealthLimitation.translations[0]?.description || null,
        })),
        TargetBodyParts: userProfile.TargetBodyParts.map(item => ({
            id: item.GoalBodyPart.goalBodyPartId,
            name: item.GoalBodyPart.translations[0]?.name || 'N/A',
            description: item.GoalBodyPart.translations[0]?.description || null,
        })),
        AvailableEquipment: userProfile.AvailableEquipment.map(item => ({
            id: item.WorkoutEquipment.workoutEquipmentId,
            name: item.WorkoutEquipment.translations[0]?.name || 'N/A',
            description: item.WorkoutEquipment.translations[0]?.description || null,
        })),
        WorkoutLocations: userProfile.WorkoutLocations.map(item => ({
            id: item.WorkoutLocation.workoutLocationId,
            name: item.WorkoutLocation.translations[0]?.name || 'N/A',
            description: item.WorkoutLocation.translations[0]?.description || null,
        })),
    };

    return formattedProfile;
};

// TODO: 'updateMyProfileService' will be added here in the future