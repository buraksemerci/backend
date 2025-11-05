// Dosya: src/utils/zod.schemas.ts
import { z } from 'zod';

// ===================================
// TEMEL BLOKLAR (Export EDİLMEYEN)
// ===================================

const userProfileSchema = z.object({
    firstName: z.string().min(2),
    lastName: z.string().min(2),
    birthDate: z.string().datetime(),
    gender: z.string().min(1),
});

const userBodySchema = z.object({
    heightCM: z.number().positive(),
    weightKG: z.number().positive(),
    activityLevel: z.string().min(1),
    bodyType: z.string().min(1),
});

const userGoalSchema = z.object({
    primaryGoal: z.string().min(1),
    targetWeightKG: z.number().positive().nullable().optional(),
});

const userSettingSchema = z.object({
    preferredUnit: z.string().min(1),
    preferredLanguage: z.string().default('tr'),
    theme: z.string().default('system'),
});

// ===================================
// === YENİ YENİDEN KULLANILABİLİR PROFİL ŞEMASI ===
// ===================================
export const profileDataSchema = z.object({
    // 1:1 Profil Verileri
    profile: userProfileSchema,
    body: userBodySchema,
    goal: userGoalSchema,
    settings: userSettingSchema,

    // M:N İlişki ID'leri
    healthLimitationIds: z.array(z.number().int()).default([]),
    targetBodyPartIds: z.array(z.number().int()).min(1),
    availableEquipmentIds: z.array(z.number().int()).min(1),
    workoutLocationIds: z.array(z.number().int()).min(1),
});

// === YENİ TİP (ZOD'DAN ÇIKARILAN) ===
export type ProfileCreationInput = z.infer<typeof profileDataSchema>;

// ===================================
// ANA KAYIT (REGISTER) ŞEMASI (GÜNCELLENDİ)
// ===================================
export const registerSchema = z.object({
    body: z.object({
        // Auth'a özel alanlar
        email: z.string().email(),
        password: z.string().min(8),
        username: z.string().min(3),
        deviceId: z.string().min(1),
    }).merge(profileDataSchema), // <-- Ortak profil verilerini buraya ekle
});

// ===================================
// GİRİŞ (LOGIN) ŞEMASI
// ===================================
export const loginSchema = z.object({
    body: z.object({
        loginIdentifier: z.string().min(3),
        password: z.string().min(1),
        deviceId: z.string().min(1),
    }),
});

// ===================================
// KOD DOĞRULAMA (VERIFY CODE) ŞEMASI
// ===================================
export const verifyCodeSchema = z.object({
    body: z.object({
        code: z
            .string()
            .min(6)
            .max(6),
        deviceId: z.string().min(1),
    }),
});

// ===================================
// ŞİFRE UNUTTUM (FORGOT PASSWORD) ŞEMASI
// ===================================
export const forgotPasswordSchema = z.object({
    body: z.object({
        email: z.string().email(),
    }),
});

// ===================================
// ŞİFRE SIFIRLAMA (RESET PASSWORD) ŞEMASI
// ===================================
export const resetPasswordSchema = z.object({
    body: z.object({
        email: z.string().email(),
        code: z
            .string()
            .min(6)
            .max(6),
        newPassword: z.string().min(8),
    }),
});

// ===================================
// SOSYAL GİRİŞ (SOCIAL) ŞEMALARI
// ===================================
const socialProviderEnum = z.enum(['GOOGLE', 'APPLE', 'FACEBOOK']);

// === SOSYAL KAYIT (GÜNCELLENDİ) ===
export const socialRegisterSchema = z.object({
    body: z.object({
        // Sosyal Auth'a özel alanlar
        provider: socialProviderEnum,
        providerToken: z.string().min(1),
        username: z.string().min(3),
        deviceId: z.string().min(1),
    }).merge(profileDataSchema), // <-- Ortak profil verilerini buraya ekle
});

// === SOSYAL GİRİŞ ===
export const socialLoginSchema = z.object({
    body: z.object({
        provider: socialProviderEnum,
        providerToken: z.string().min(1),
        deviceId: z.string().min(1),
    }),
});

// === SOSYAL BİRLEŞTİRME ===
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
// TÜM TİP ÇIKARIMLARI (TYPE INFERENCES)
// ===================================
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

// (ProfileCreationInput artık yukarıda, profileDataSchema'nın hemen altında tanımlı)