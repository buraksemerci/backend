import { z } from 'zod';

// ===================================
// TEMEL BLOKLAR (Export EDİLMEYEN)
// ===================================

// (Bu şemalar değişmedi, sadece artık export edilmiyorlar)
const userProfileSchema = z.object({
    firstName: z.string().min(2, 'Ad en az 2 karakter olmalıdır.'),
    lastName: z.string().min(2, 'Soyad en az 2 karakter olmalıdır.'),
    birthDate: z.string().datetime('Geçersiz doğum tarihi formatı (ISO 8601).'),
    gender: z.string().min(1, 'Cinsiyet seçimi zorunludur.'),
});

const userBodySchema = z.object({
    heightCM: z.number().positive('Boy pozitif bir sayı olmalıdır.'),
    weightKG: z.number().positive('Kilo pozitif bir sayı olmalıdır.'),
    activityLevel: z.string().min(1, 'Aktivite seviyesi zorunludur.'),
    bodyType: z.string().min(1, 'Vücut tipi zorunludur.'),
});

const userGoalSchema = z.object({
    primaryGoal: z.string().min(1, 'Ana hedef zorunludur.'),
    targetWeightKG: z.number().positive('Hedef kilo pozitif olmalı.').nullable().optional(),
});

const userSettingSchema = z.object({
    preferredUnit: z.string().min(1, 'Birim tercihi zorunludur.'),
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
    targetBodyPartIds: z.array(z.number().int()).min(1, 'En az bir hedef bölge seçmelisiniz.'),
    availableEquipmentIds: z.array(z.number().int()).min(1, 'En az bir ekipman seçmelisiniz.'),
    workoutLocationIds: z.array(z.number().int()).min(1, 'En az bir antrenman konumu seçmelisiniz.'),
});

// === YENİ TİP (ZOD'DAN ÇIKARILAN) ===
export type ProfileCreationInput = z.infer<typeof profileDataSchema>;

// ===================================
// ANA KAYIT (REGISTER) ŞEMASI (GÜNCELLENDİ)
// ===================================
export const registerSchema = z.object({
    body: z.object({
        // Auth'a özel alanlar
        email: z.string().email('Geçersiz e-posta adresi.'),
        password: z.string().min(8, 'Şifre en az 8 karakter olmalıdır.'),
        username: z.string().min(3, 'Kullanıcı adı en az 3 karakter olmalıdır.'),
        deviceId: z.string().min(1, 'Cihaz ID zorunludur.'),
    }).merge(profileDataSchema), // <-- Ortak profil verilerini buraya ekle
});

// ===================================
// GİRİŞ (LOGIN) ŞEMASI
// ===================================
export const loginSchema = z.object({
    body: z.object({
        loginIdentifier: z.string().min(3, 'Giriş bilgisi gerekli.'),
        password: z.string().min(1, 'Şifre gerekli.'),
        deviceId: z.string().min(1, 'Cihaz ID zorunludur.'),
    }),
});

// ===================================
// KOD DOĞRULAMA (VERIFY CODE) ŞEMASI
// ===================================
export const verifyCodeSchema = z.object({
    body: z.object({
        code: z
            .string()
            .min(6, 'Kod 6 haneli olmalıdır.')
            .max(6, 'Kod 6 haneli olmalıdır.'),
        deviceId: z.string().min(1, 'Cihaz ID zorunludur.'),
    }),
});

// ===================================
// ŞİFRE UNUTTUM (FORGOT PASSWORD) ŞEMASI
// ===================================
export const forgotPasswordSchema = z.object({
    body: z.object({
        email: z.string().email('Geçersiz e-posta adresi.'),
    }),
});

// ===================================
// ŞİFRE SIFIRLAMA (RESET PASSWORD) ŞEMASI
// ===================================
export const resetPasswordSchema = z.object({
    body: z.object({
        email: z.string().email('Geçersiz e-posta adresi.'),
        code: z
            .string()
            .min(6, 'Kod 6 haneli olmalıdır.')
            .max(6, 'Kod 6 haneli olmalıdır.'),
        newPassword: z.string().min(8, 'Yeni şifre en az 8 karakter olmalıdır.'),
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
        providerToken: z.string().min(1, 'Provider token zorunludur.'),
        username: z.string().min(3, 'Kullanıcı adı en az 3 karakter olmalıdır.'),
        deviceId: z.string().min(1, 'Cihaz ID zorunludur.'),
    }).merge(profileDataSchema), // <-- Ortak profil verilerini buraya ekle
});

// === SOSYAL GİRİŞ ===
export const socialLoginSchema = z.object({
    body: z.object({
        provider: socialProviderEnum,
        providerToken: z.string().min(1, 'Provider token zorunludur.'),
        deviceId: z.string().min(1, 'Cihaz ID zorunludur.'),
    }),
});

// === SOSYAL BİRLEŞTİRME ===
export const socialMergeSchema = z.object({
    body: z.object({
        provider: socialProviderEnum,
        providerToken: z.string().min(1, 'Provider token zorunludur.'),
        password: z.string().min(1, 'Şifre zorunludur.'),
        deviceId: z.string().min(1, 'Cihaz ID zorunludur.'),
    }),
});

// ===================================
// OTURUM (SESSION) ŞEMALARI
// ===================================
export const refreshSchema = z.object({
    body: z.object({
        refreshToken: z.string().min(1, 'Refresh token zorunludur.'),
        deviceId: z.string().min(1, 'Cihaz ID zorunludur.'),
    }),
});

export const logoutSchema = z.object({
    body: z.object({
        deviceId: z.string().min(1, 'Cihaz ID zorunludur.'),
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