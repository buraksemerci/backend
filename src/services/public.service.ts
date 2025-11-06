// Dosya: src/services/public.service.ts
import prisma from '../utils/prisma';
import { GENDER_IDS, CONTENT_TYPES } from '../utils/constants'; // Sabitleri import et

// --- YARDIMCI FONKSİYONLAR ---
// (profile.service.ts'de kullandıklarımızla aynı)

const DEFAULT_LANG = 'tr';
const FALLBACK_LANG = 'en';

const getLanguagesToTry = (languageCode: string) => {
    return [...new Set([languageCode, DEFAULT_LANG, FALLBACK_LANG])];
};

type Translation = {
    name: string;
    description?: string | null;
    languageCode: string;
};

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

/**
 * GÜNCELLENDİ: Ana veri listesini formatlayan genel yardımcı
 * (Artık ID'ler String (UUID) bekliyor)
 */
const formatList = (
    items: (any & { translations: Translation[] })[],
    idField: string,
    languageCode: string,
) => {
    return items
        .map((item) => {
            const t = getPreferredTranslation(item.translations, languageCode);
            return {
                id: item[idField], // UUID
                name: t.name,
                description: t.description,
            };
        })
        .sort((a, b) => a.name.localeCompare(b.name));
};

/**
 * YENİ: Sadece çeviri gerektiren basit ana verileri çeker
 * (ActivityLevel, BodyType, GoalType vb. için)
 */
const getTranslatedMasterData = async (
    model: any, // örn: prisma.goalType
    idField: string,
    languageCode: string,
) => {
    const languages = getLanguagesToTry(languageCode);
    const items = await model.findMany({
        select: {
            [idField]: true,
            translations: {
                where: { languageCode: { in: languages } },
                select: { name: true, description: true, languageCode: true },
            },
        },
    });
    return formatList(items, idField, languageCode);
};

/**
 * GÜNCELLENDİ: ContentAudience'a göre filtreleme yapan ana fonksiyon
 * (HealthLimitation, GoalBodyPart için)
 */
const getAudienceFilteredData = async (
    model: any, // örn: prisma.healthLimitation
    idField: string,
    contentType: string, // örn: CONTENT_TYPES.LIMITATION
    languageCode: string,
    genderId: number | null = null,
) => {
    const languages = getLanguagesToTry(languageCode);

    // Filtreleme mantığını oluştur (Öneri 3b)
    const audienceFilter: any = {
        some: {
            contentType: contentType,
        },
    };

    // Eğer bir cinsiyet ('male', 'female', 'unknown') geldiyse,
    // sadece o cinsiyete veya 'all' (herkes) olarak işaretlenmiş olanları getir.
    if (genderId) {
        audienceFilter.some.genderId = { in: [genderId, GENDER_IDS.ALL] };
    }

    const items = await model.findMany({
        where: {
            ContentAudience: audienceFilter,
        },
        select: {
            [idField]: true,
            translations: {
                where: { languageCode: { in: languages } },
                select: { name: true, description: true, languageCode: true },
            },
        },
    });

    return formatList(items, idField, languageCode);
};

// ==========================================================
// MEVCUT SERVİSLER (GÜNCELLENDİ)
// ==========================================================

// GÜNCELLENDİ: Artık 'genderId' alıyor ve ContentAudience'a göre filtreleniyor
export const getLimitationService = async (
    languageCode: string,
    genderId?: number | null,
) => {
    return getAudienceFilteredData(
        prisma.healthLimitation,
        'healthLimitationId',
        CONTENT_TYPES.LIMITATION,
        languageCode,
        genderId,
    );
};

// GÜNCELLENDİ: Artık 'genderId' alıyor ve ContentAudience'a göre filtreleniyor
export const getBodyPartService = async (
    languageCode: string,
    genderId?: number | null,
) => {
    return getAudienceFilteredData(
        prisma.goalBodyPart,
        'goalBodyPartId',
        CONTENT_TYPES.BODY_PART,
        languageCode,
        genderId,
    );
};

// GÜNCELLENDİ: (Bu tablolar şimdilik Audience filtresi kullanmıyor, basit listeleme)
export const getEquipmentService = async (languageCode: string) => {
    return getTranslatedMasterData(
        prisma.workoutEquipment,
        'workoutEquipmentId',
        languageCode,
    );
};

// GÜNCELLENDİ: (Bu tablolar şimdilik Audience filtresi kullanmıyor, basit listeleme)
export const getLocationService = async (languageCode: string) => {
    return getTranslatedMasterData(
        prisma.workoutLocation,
        'workoutLocationId',
        languageCode,
    );
};

// ==========================================================
// YENİ SERVİSLER (Normalize Edilmiş Ana Veri için)
// ==========================================================

export const getActivityLevelService = async (languageCode: string) => {
    return getTranslatedMasterData(
        prisma.activityLevel,
        'activityLevelId',
        languageCode,
    );
};

export const getBodyTypeService = async (languageCode: string) => {
    return getTranslatedMasterData(
        prisma.bodyType,
        'bodyTypeId',
        languageCode,
    );
};

export const getFitnessLevelService = async (languageCode: string) => {
    return getTranslatedMasterData(
        prisma.fitnessLevel,
        'fitnessLevelId',
        languageCode,
    );
};

export const getGoalTypeService = async (languageCode: string) => {
    return getTranslatedMasterData(
        prisma.goalType,
        'goalTypeId',
        languageCode,
    );
};

export const getGenderService = async (languageCode: string) => {
    // Gender tablosunda çeviri yok, 'key' alanını direkt kullanıyoruz
    const items = await prisma.gender.findMany({
        select: {
            genderId: true,
            key: true,
        },
    });

    // (formatList helper'ı 'translations' beklediği için burada manuel map yapıyoruz)
    return items.map(item => ({
        id: item.genderId,
        name: item.key, // 'key'i 'name' olarak map'liyoruz
        description: null,
    }));
};