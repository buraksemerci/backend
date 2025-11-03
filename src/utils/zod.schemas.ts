import { z } from 'zod';

// ===================================
// TEMEL PROFİL ŞEMALARI (BUNLAR AYNI)
// ===================================
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
// ANA KAYIT (REGISTER) ŞEMASI (YENİ)
// ===================================

export const registerSchema = z.object({
    body: z.object({
        // Auth
        email: z.string().email('Geçersiz e-posta adresi.'),
        password: z.string().min(8, 'Şifre en az 8 karakter olmalıdır.'),
        username: z.string().min(3, 'Kullanıcı adı en az 3 karakter olmalıdır.'),

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
    }),
});

// ===================================
// GİRİŞ (LOGIN) ŞEMASI (YENİ)
// ===================================

export const loginSchema = z.object({
    body: z.object({
        loginIdentifier: z.string().min(3, 'Giriş bilgisi gerekli.'),
        password: z.string().min(1, 'Şifre gerekli.'),
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
// Hangi sağlayıcıları kabul ettiğimizi tanımlayan bir enum
const socialProviderEnum = z.enum(['GOOGLE', 'APPLE', 'FACEBOOK']);

// ===================================
// SOSYAL KAYIT (SOCIAL REGISTER) ŞEMASI
// ===================================
export const socialRegisterSchema = z.object({
    body: z.object({
        // Auth (Lokal yerine Sosyal)
        provider: socialProviderEnum, // "GOOGLE"
        providerToken: z.string().min(1, 'Provider token zorunludur.'),

        // === YENİ (SİZİN TALEBİNİZ ÜZERİNE EKLENDİ) ===
        // 'register' akışıyla aynı olması için username'i zorunlu kılıyoruz.
        username: z.string().min(3, 'Kullanıcı adı en az 3 karakter olmalıdır.'),
        // ============================================

        // 1:1 Profil Verileri (Lokal kayıt ile aynı)
        profile: userProfileSchema,
        body: userBodySchema,
        goal: userGoalSchema,
        settings: userSettingSchema,

        // M:N İlişki ID'leri (Lokal kayıt ile aynı)
        healthLimitationIds: z.array(z.number().int()).default([]),
        targetBodyPartIds: z.array(z.number().int()).min(1, 'En az bir hedef bölge seçmelisiniz.'),
        availableEquipmentIds: z.array(z.number().int()).min(1, 'En az bir ekipman seçmelisiniz.'),
        workoutLocationIds: z.array(z.number().int()).min(1, 'En az bir antrenman konumu seçmelisiniz.'),
    }),
});

// ===================================
// SOSYAL GİRİŞ (SOCIAL LOGIN) ŞEMASI
// ===================================
export const socialLoginSchema = z.object({
    body: z.object({
        provider: socialProviderEnum, // "GOOGLE", "APPLE", "FACEBOOK"
        providerToken: z.string().min(1, 'Provider token zorunludur.'),
    }),
});

// ===================================
// SOSYAL BİRLEŞTİRME (SOCIAL MERGE) ŞEMASI
// ===================================
export const socialMergeSchema = z.object({
    body: z.object({
        provider: socialProviderEnum, // "GOOGLE", "APPLE", "FACEBOOK"
        providerToken: z.string().min(1, 'Provider token zorunludur.'),
        password: z.string().min(1, 'Şifre zorunludur.'),
    }),
});

// ===================================
// TOKEN YENİLEME (REFRESH TOKEN) ŞEMASI
// ===================================
export const refreshSchema = z.object({
    body: z.object({
        refreshToken: z.string().min(1, 'Refresh token zorunludur.'),
    }),
});

export type SocialMergeInput = z.infer<typeof socialMergeSchema>;
export type SocialLoginInput = z.infer<typeof socialLoginSchema>;
export type SocialRegisterInput = z.infer<typeof socialRegisterSchema>;
export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>;
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;
export type VerifyCodeInput = z.infer<typeof verifyCodeSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type RegisterInput = z.infer<typeof registerSchema>;
export type RefreshInput = z.infer<typeof refreshSchema>;