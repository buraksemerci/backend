// Dosya: src/services/profile.service.ts
import prisma from '../utils/prisma';
import logger from '../utils/logger';

// --- YARDIMCI FONKSİYONLAR ---
// (public.service.ts'deki mantığın aynısı, çevirileri tutarlı işlemek için)

const DEFAULT_LANG = 'tr';
const FALLBACK_LANG = 'en';

/**
 * Veritabanında sorgulanacak dillerin öncelik sırasını belirler.
 * @param languageCode Kullanıcının tercih ettiği dil (örn: 'de')
 * @returns Denenecek dillerin dizisi (örn: ['de', 'tr', 'en'])
 */
const getLanguagesToTry = (languageCode: string) => {
    return [...new Set([languageCode, DEFAULT_LANG, FALLBACK_LANG])];
};

type Translation = {
    name: string;
    description?: string | null;
    languageCode: string;
};

/**
 * Bir çeviri dizisinden, istenen dile veya yedek dillere göre
 * en uygun çeviriyi seçer.
 * @param translations Veritabanından gelen çeviri dizisi
 * @param languageCode Kullanıcının tercih ettiği dil
 * @returns En uygun çeviri nesnesi (veya varsayılan)
 */
const getPreferredTranslation = (
    translations: Translation[],
    languageCode: string,
) => {
    const t =
        translations.find((tr) => tr.languageCode === languageCode) ||
        translations.find((tr) => tr.languageCode === DEFAULT_LANG) ||
        translations.find((tr) => tr.languageCode === FALLBACK_LANG);

    return {
        name: t?.name || 'N/A',
        description: t?.description || null,
    };
};

// --- ANA PROFİL SERVİSİ (GÜNCELLENDİ) ---

/**
 * Giriş yapmış kullanıcının TÜM normalize edilmiş profil verilerini
 * (1:1, M:N, Çeviriler) getirir.
 * @param {string} userId - JWT'den gelen kullanıcı UUID'si
 */
export const getMyProfileService = async (userId: string) => {

    // --- Adım 1: Kullanıcının tercih ettiği dili bul ---
    let languageCode = DEFAULT_LANG;
    try {
        const settings = await prisma.userSetting.findUnique({
            where: { userId },
            select: { preferredLanguage: true },
        });
        if (settings?.preferredLanguage) {
            languageCode = settings.preferredLanguage;
        }
    } catch (e) {
        logger.warn(e, `[ProfileService] ${userId} için dil ayarı bulunamadı, varsayılan 'tr' kullanılıyor.`);
    }

    const languagesToTry = getLanguagesToTry(languageCode);

    // --- Adım 2: Tüm veriyi yeni şemaya göre çek (GÜNCELLENDİ) ---
    const userProfile = await prisma.user.findUnique({
        where: { userId },
        select: {
            // Temel Kullanıcı verisi
            userId: true,
            email: true,
            username: true,
            isEmailVerified: true,
            createdAt: true,

            // 1:1 Normalize Edilmiş Veriler (GÜNCELLENDİ)
            Profile: {
                include: {
                    Gender: true, // Cinsiyet (ID + Key)
                },
            },
            Body: {
                include: {
                    ActivityLevel: { include: { translations: { where: { languageCode: { in: languagesToTry } } } } },
                    BodyType: { include: { translations: { where: { languageCode: { in: languagesToTry } } } } },
                    FitnessLevel: { include: { translations: { where: { languageCode: { in: languagesToTry } } } } },
                },
            },
            Goal: {
                include: {
                    GoalType: { include: { translations: { where: { languageCode: { in: languagesToTry } } } } },
                },
            },
            Setting: true, // Ayarlar (1:1)
            ProgramPreference: { // Tercihler (1:1)
                include: {
                    PreferredEquipment: { include: { translations: { where: { languageCode: { in: languagesToTry } } } } }
                }
            },

            // M:N İlişkili Veriler (Sorgu mantığı aynı, ID'ler artık UUID)
            HealthLimitation: {
                select: {
                    HealthLimitation: {
                        select: {
                            healthLimitationId: true,
                            translations: {
                                where: { languageCode: { in: languagesToTry } },
                                select: { name: true, description: true, languageCode: true },
                            },
                        },
                    },
                },
            },
            TargetBodyPart: {
                select: {
                    GoalBodyPart: {
                        select: {
                            goalBodyPartId: true,
                            translations: {
                                where: { languageCode: { in: languagesToTry } },
                                select: { name: true, description: true, languageCode: true },
                            },
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
                                select: { name: true, description: true, languageCode: true },
                            },
                        },
                    },
                },
            },
            WorkoutLocation: {
                select: {
                    WorkoutLocation: {
                        select: {
                            workoutLocationId: true,
                            translations: {
                                where: { languageCode: { in: languagesToTry } },
                                select: { name: true, description: true, languageCode: true },
                            },
                        },
                    },
                },
            },
        },
    });

    if (!userProfile) {
        throw new Error('USER_NOT_FOUND');
    }

    // --- Adım 3: Veriyi temizle ve formatla (GÜNCELLENDİ) ---

    // Helper: 1:1 ilişkilerdeki çevirileri temizler
    const formatTranslatedField = (field: { translations: Translation[] } | null | undefined) => {
        if (!field) return null;
        return getPreferredTranslation(field.translations, languageCode).name;
    };

    // Helper: M:N ilişkilerdeki çevirileri temizler
    const formatTranslatedList = (list: any[], relationName: string, idField: string) => {
        return list.map((item) => {
            const entity = item[relationName];
            const t = getPreferredTranslation(entity.translations, languageCode);
            return {
                id: entity[idField], // Artık bir UUID
                name: t.name,
                description: t.description,
            };
        });
    };

    const formattedProfile = {
        // Temel veriler
        userId: userProfile.userId,
        email: userProfile.email,
        username: userProfile.username,
        isEmailVerified: userProfile.isEmailVerified,
        createdAt: userProfile.createdAt,

        // 1:1 Normalize edilmiş veriler
        Profile: {
            firstName: userProfile.Profile?.firstName,
            lastName: userProfile.Profile?.lastName,
            birthDate: userProfile.Profile?.birthDate,
            gender: userProfile.Profile?.Gender?.key, // 'genderId' (Int) yerine 'gender' (String "male") gönder
        },
        Body: {
            heightCM: userProfile.Body?.heightCM,
            weightKG: userProfile.Body?.weightKG,
            activityLevel: formatTranslatedField(userProfile.Body?.ActivityLevel), // 'activityLevelId' yerine çevrilmiş 'name'
            bodyType: formatTranslatedField(userProfile.Body?.BodyType),
            fitnessLevel: formatTranslatedField(userProfile.Body?.FitnessLevel),
        },
        Goal: {
            primaryGoal: formatTranslatedField(userProfile.Goal?.GoalType), // 'goalTypeId' yerine çevrilmiş 'name'
            targetWeightKG: userProfile.Goal?.targetWeightKG,
        },
        Setting: userProfile.Setting,
        ProgramPreference: {
            workoutDuration: userProfile.ProgramPreference?.workoutDuration,
            startWithWarmup: userProfile.ProgramPreference?.startWithWarmup,
            preferredEquipment: formatTranslatedField(userProfile.ProgramPreference?.PreferredEquipment)
        },

        // M:N Çevrilmiş veriler
        HealthLimitations: formatTranslatedList(
            userProfile.HealthLimitation,
            'HealthLimitation',
            'healthLimitationId'
        ),
        TargetBodyParts: formatTranslatedList(
            userProfile.TargetBodyPart,
            'GoalBodyPart',
            'goalBodyPartId'
        ),
        AvailableEquipment: formatTranslatedList(
            userProfile.AvailableEquipment,
            'WorkoutEquipment',
            'workoutEquipmentId'
        ),
        WorkoutLocations: formatTranslatedList(
            userProfile.WorkoutLocation,
            'WorkoutLocation',
            'workoutLocationId'
        ),
    };

    return formattedProfile;
};