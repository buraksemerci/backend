// Dosya: src/utils/zod.schemas.ts
import { z } from 'zod';

// ===================================
// TEMEL BLOKLAR (GÜNCELLENDİ)
// ===================================

const userProfileSchema = z.object({
    firstName: z.string().min(2),
    lastName: z.string().min(2),
    birthDate: z.string().datetime(),
    genderId: z.number().int().min(1).max(4).optional().nullable(),
});

const userBodySchema = z.object({
    heightCM: z.number().positive(),
    weightKG: z.number().positive(),
    activityLevelId: z.number().int(),
    bodyTypeId: z.number().int(),
    fitnessLevelId: z.number().int(),
});

const userGoalSchema = z.object({
    goalTypeId: z.number().int(),
    targetWeightKG: z.number().positive().nullable().optional(),
});

const userSettingSchema = z.object({
    preferredUnit: z.string().min(1),
    preferredLanguage: z.string().default('tr'),
    theme: z.string().default('system'),
});

const userProgramPreferenceSchema = z.object({
    workoutDuration: z.number().int().optional().nullable(),
    startWithWarmup: z.boolean().default(true),
    // DEĞİŞTİ: z.string().uuid() -> z.number().int()
    workoutEquipmentId: z.number().int().optional().nullable(),
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
    preference: userProgramPreferenceSchema,

    // M:N İlişki ID'leri (DEĞİŞTİ: z.string().uuid() -> z.number().int())
    healthLimitationIds: z.array(z.number().int()).default([]),
    targetBodyPartIds: z.array(z.number().int()).min(1),
    availableEquipmentIds: z.array(z.number().int()).min(1),
    workoutLocationIds: z.array(z.number().int()).min(1), // .min(1) kuralı orijinal dosyada vardı

    // "Kayıt anında program atama" stratejimiz için YENİ alan
    workoutDays: z.array(z.number().int().min(0).max(6)).min(1).max(7),
});

export type ProfileCreationInput = z.infer<typeof profileDataSchema>;

// ===================================
// MEVCUT AUTH ŞEMALARI (Otomatik olarak güncellendiler)
// ===================================

export const registerSchema = z.object({
    body: z.object({
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

const socialProviderEnum = z.enum(['GOOGLE', 'APPLE', 'FACEBOOK']);

export const socialRegisterSchema = z.object({
    body: z.object({
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
// OTURUM (SESSION) ŞEMALARI
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
// KULLANICI TAKVİM (SCHEDULE) ŞEMALARI
// ===================================

const dayAssignmentSchema = z.object({
    dayOfWeek: z.number().int().min(0).max(6),
    // (programId UUID olarak kaldı, bu doğru)
    programId: z.string().uuid().optional().nullable(),
    isRestDay: z.boolean().default(false),
}).refine(data => {
    return !(data.programId && data.isRestDay);
}, {
    message: "A day cannot be both a rest day and have a program assigned.",
    path: ["programId", "isRestDay"],
});

export const updateScheduleSchema = z.object({
    body: z.object({
        assignments: z.array(dayAssignmentSchema).length(7, "You must provide all 7 days of the week."),
    }),
});
// ===================================
// TÜM TİP ÇIKARIMLARI
// ===================================
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