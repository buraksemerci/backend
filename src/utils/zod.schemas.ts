// Dosya: src/utils/zod.schemas.ts
import { z } from 'zod';

// ===================================
// TEMEL BLOKLAR (GÜNCELLENDİ)
// ===================================

// Öneri 2e/2b: 'gender' -> 'genderId' (Int, isteğe bağlı)
const userProfileSchema = z.object({
    firstName: z.string().min(2),
    lastName: z.string().min(2),
    birthDate: z.string().datetime(),
    genderId: z.number().int().min(1).max(4).optional().nullable(), // Artık Int ve isteğe bağlı
});

// Öneri 2b: String'ler ID'lere dönüştü (Normalleştirildi)
const userBodySchema = z.object({
    heightCM: z.number().positive(),
    weightKG: z.number().positive(),
    activityLevelId: z.number().int(), // 'activityLevel' -> 'activityLevelId'
    bodyTypeId: z.number().int(),      // 'bodyType' -> 'bodyTypeId'
    fitnessLevelId: z.number().int(),  // YENİ
});

// Öneri 2b: String'ler ID'lere dönüştü (Normalleştirildi)
const userGoalSchema = z.object({
    goalTypeId: z.number().int(), // 'primaryGoal' -> 'goalTypeId'
    targetWeightKG: z.number().positive().nullable().optional(),
});

const userSettingSchema = z.object({
    preferredUnit: z.string().min(1),
    preferredLanguage: z.string().default('tr'),
    theme: z.string().default('system'),
});

// YENİ: Kullanıcı tercihlerini kayıt anında almak için
const userProgramPreferenceSchema = z.object({
    workoutDuration: z.number().int().optional().nullable(),
    startWithWarmup: z.boolean().default(true),
    // Öneri 2a (UUID): workoutEquipmentId artık Int değil, String (UUID)
    workoutEquipmentId: z.string().uuid().optional().nullable(),
});

// ===================================
// ANA KAYIT PROFİL ŞEMASI (GÜNCELLENDİ)
// ===================================
export const profileDataSchema = z.object({
    // 1:1 Profil Verileri
    profile: userProfileSchema,
    body: userBodySchema,
    goal: userGoalSchema,
    settings: userSettingSchema,
    preference: userProgramPreferenceSchema, // YENİ

    // M:N İlişki ID'leri (Öneri 2a: Artık Int değil, String UUID olmalılar)
    healthLimitationIds: z.array(z.string().uuid()).default([]),
    targetBodyPartIds: z.array(z.string().uuid()).min(1),
    availableEquipmentIds: z.array(z.string().uuid()).min(1),
    workoutLocationIds: z.array(z.string().uuid()).min(1),

    // "Kayıt anında program atama" stratejimiz için YENİ alan
    // (0 = Pazar, 1 = Pzt, 2 = Salı, 3 = Çar, 4 = Per, 5 = Cuma, 6 = Cmt)
    workoutDays: z.array(z.number().int().min(0).max(6)).min(1).max(7),
});

// (Bu tip, auth.service.ts'i güncellerken kilit rol oynayacak)
export type ProfileCreationInput = z.infer<typeof profileDataSchema>;

// ===================================
// MEVCUT AUTH ŞEMALARI (DEĞİŞİKLİK YOK - Ana Mantık Korundu)
// ===================================

// (registerSchema, profileDataSchema'yı merge ettiği için otomatik olarak güncellendi)
export const registerSchema = z.object({
    body: z.object({
        // Auth'a özel alanlar
        email: z.string().email(),
        password: z.string().min(8),
        username: z.string().min(3),
        deviceId: z.string().min(1),
    }).merge(profileDataSchema), // <-- GÜNCELLENMİŞ profileDataSchema'yı kullanır
});

export const loginSchema = z.object({
    body: z.object({
        loginIdentifier: z.string().min(3),
        password: z.string().min(1),
        deviceId: z.string().min(1),
    }),
});

export const verifyCodeSchema = z.object({
    body: z.object({
        code: z.string().min(6).max(6),
        deviceId: z.string().min(1),
    }),
});

export const forgotPasswordSchema = z.object({
    body: z.object({
        email: z.string().email(),
    }),
});

export const resetPasswordSchema = z.object({
    body: z.object({
        email: z.string().email(),
        code: z.string().min(6).max(6),
        newPassword: z.string().min(8),
    }),
});

// (socialRegisterSchema da profileDataSchema'yı merge ettiği için otomatik güncellendi)
const socialProviderEnum = z.enum(['GOOGLE', 'APPLE', 'FACEBOOK']);

export const socialRegisterSchema = z.object({
    body: z.object({
        // Sosyal Auth'a özel alanlar
        provider: socialProviderEnum,
        providerToken: z.string().min(1),
        username: z.string().min(3),
        deviceId: z.string().min(1),
    }).merge(profileDataSchema), // <-- GÜNCELLENMİŞ profileDataSchema'yı kullanır
});

export const socialLoginSchema = z.object({
    body: z.object({
        provider: socialProviderEnum,
        providerToken: z.string().min(1),
        deviceId: z.string().min(1),
    }),
});

export const socialMergeSchema = z.object({
    body: z.object({
        provider: socialProviderEnum,
        providerToken: z.string().min(1),
        password: z.string().min(1),
        deviceId: z.string().min(1),
    }),
});

// ===================================
// OTURUM (SESSION) ŞEMALARI (DEĞİŞİKLİK YOK)
// ===================================
export const refreshSchema = z.object({
    body: z.object({
        refreshToken: z.string().min(1),
        deviceId: z.string().min(1),
    }),
});

export const logoutSchema = z.object({
    body: z.object({
        deviceId: z.string().min(1),
    }),
});

// ===================================
// TÜM TİP ÇIKARIMLARI (DEĞİŞİKLİK YOK)
// ===================================
// ===================================
// YENİ: KULLANICI TAKVİM (SCHEDULE) ŞEMALARI
// ===================================

// Kullanıcının bir günü nasıl güncelleyeceğini tanımlar:
// Ya bir programId verir (antrenman günü)
// Ya da isRestDay: true verir (dinlenme günü)
const dayAssignmentSchema = z.object({
    dayOfWeek: z.number().int().min(0).max(6), // 0-6 (Pazar-Cmt)
    programId: z.string().uuid().optional().nullable(), // Hangi programı atadığı
    isRestDay: z.boolean().default(false), // Veya dinlenme günü mü?
}).refine(data => {
    // Aynı anda hem programId hem de isRestDay: true olamaz
    return !(data.programId && data.isRestDay);
}, {
    message: "A day cannot be both a rest day and have a program assigned.",
    path: ["programId", "isRestDay"],
});

// Kullanıcı bize 7 günlük tam bir dizi göndermeli
export const updateScheduleSchema = z.object({
    body: z.object({
        assignments: z.array(dayAssignmentSchema).length(7, "You must provide all 7 days of the week."),
    }),
});

export type UpdateScheduleInput = z.infer<typeof updateScheduleSchema>;
export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type VerifyCodeInput = z.infer<typeof verifyCodeSchema>;
export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>;
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;
export type SocialRegisterInput = z.infer<typeof socialRegisterSchema>;
export type SocialLoginInput = z.infer<typeof socialLoginSchema>;
export type SocialMergeInput = z.infer<typeof socialMergeSchema>;
export type RefreshInput = z.infer<typeof refreshSchema>;
export type LogoutInput = z.infer<typeof logoutSchema>;