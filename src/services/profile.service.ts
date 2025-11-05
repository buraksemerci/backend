import prisma from '../utils/prisma';
import logger from '../utils/logger';

/**
 * Giriş yapmış kullanıcının tüm profil verilerini getirir.
 * (Temel User bilgisi, 1:1 Profil, Vücut, Hedef, Ayarlar ve M:N ilişkileri)
 * @param {string} userId - JWT'den gelen kullanıcı ID'si
 */
export const getMyProfileService = async (userId: string) => {

    // --- 1. Adım: Kullanıcının tercih ettiği dili al ---
    // (veya varsayılan olarak 'tr' kullan)
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
        logger.warn(e, `Kullanıcı ${userId} için dil ayarı bulunamadı, varsayılan 'tr' kullanılacak.`);
    }

    // --- 2. Adım: Tüm veriyi kullanıcının diline göre getir ---
    const userProfile = await prisma.user.findUnique({
        where: { userId },
        select: {
            // Temel User verileri
            userId: true,
            email: true,
            username: true,
            isEmailVerified: true,
            createdAt: true,

            // 1:1 İlişkili veriler (Bunlar değişmedi)
            Profile: true, // UserProfile tablosu
            Body: true,    // UserBody tablosu
            Goal: true,    // UserGoal tablosu
            Setting: true, // UserSetting tablosu

            // --- 3. Adım: M:N İlişkili veriler (YENİDEN YAZILDI) ---
            // Artık 'name' alanı için '...Translation' tablosuna bakıyoruz
            HealthLimitations: {
                select: {
                    HealthLimitation: {
                        select: {
                            healthLimitationId: true,
                            // 'translations' ilişkisinden DİLE GÖRE FİLTRELE
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

    // 2. Kullanıcı bulunamazsa
    if (!userProfile) {
        throw new Error('USER_NOT_FOUND');
    }

    // --- 4. Adım: Veriyi temizle (M:N verilerini düz bir diziye çevir) ---
    // (Artık karmaşık 'translations' dizisini düzeltmemiz gerekiyor)
    const formattedProfile = {
        ...userProfile,
        // Düzeltilmiş format: { id: 1, name: "Türkçe İsim" }
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

// TODO: Gelecekte 'updateMyProfileService' buraya eklenecek