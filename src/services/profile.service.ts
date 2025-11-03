import prisma from '../utils/prisma';

/**
 * Giriş yapmış kullanıcının tüm profil verilerini getirir.
 * (Temel User bilgisi, 1:1 Profil, Vücut, Hedef, Ayarlar ve M:N ilişkileri)
 * @param {string} userId - JWT'den gelen kullanıcı ID'si
 */
export const getMyProfileService = async (userId: string) => {
    // 1. Kullanıcıyı ve ilişkili tüm profil verilerini bul
    const userProfile = await prisma.user.findUnique({
        where: { userId },
        select: {
            // Temel User verileri
            userId: true,
            email: true,
            username: true,
            isEmailVerified: true,
            createdAt: true,

            // 1:1 İlişkili veriler
            Profile: true, // UserProfile tablosu
            Body: true,    // UserBody tablosu
            Goal: true,    // UserGoal tablosu
            Setting: true, // UserSetting tablosu

            // M:N İlişkili veriler (ara tablodan asıl veriye)
            HealthLimitations: {
                select: {
                    HealthLimitation: { // Asıl 'HealthLimitation' verisini seç
                        select: {
                            healthLimitationId: true,
                            name: true,
                        },
                    },
                },
            },
            TargetBodyParts: {
                select: {
                    GoalBodyPart: { // Asıl 'GoalBodyPart' verisini seç
                        select: {
                            goalBodyPartId: true,
                            name: true,
                        },
                    },
                },
            },
            AvailableEquipment: {
                select: {
                    WorkoutEquipment: { // Asıl 'WorkoutEquipment' verisini seç
                        select: {
                            workoutEquipmentId: true,
                            name: true,
                        },
                    },
                },
            },
            WorkoutLocations: {
                select: {
                    WorkoutLocation: { // Asıl 'WorkoutLocation' verisini seç
                        select: {
                            workoutLocationId: true,
                            name: true,
                        },
                    },
                },
            },
        },
    });

    // 2. Kullanıcı bulunamazsa (teorik olarak olmamalı, JWT'den geldi)
    if (!userProfile) {
        throw new Error('USER_NOT_FOUND');
    }

    // 3. Veriyi temizle (M:N verilerini düz bir diziye çevir)
    // (Prisma'nın M:N 'select' yapısı biraz karmaşıktır, 
    // frontend'e göndermeden önce temizlemek en iyisidir)
    const formattedProfile = {
        ...userProfile,
        HealthLimitations: userProfile.HealthLimitations.map(
            (item) => item.HealthLimitation
        ),
        TargetBodyParts: userProfile.TargetBodyParts.map(
            (item) => item.GoalBodyPart
        ),
        AvailableEquipment: userProfile.AvailableEquipment.map(
            (item) => item.WorkoutEquipment
        ),
        WorkoutLocations: userProfile.WorkoutLocations.map(
            (item) => item.WorkoutLocation
        ),
    };

    return formattedProfile;
};

// TODO: Gelecekte 'updateMyProfileService' buraya eklenecek
