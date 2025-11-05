// Dosya: src/services/public.service.ts
import prisma from '../utils/prisma';

// İstenen dil, varsayılan 'tr' ve son çare 'en'
const getLanguagesToTry = (languageCode: string) => {
    const DEFAULT_LANG = 'tr';
    const FALLBACK_LANG = 'en';
    return [...new Set([languageCode, DEFAULT_LANG, FALLBACK_LANG])];
};

// Çevirileri önceliklendiren helper fonksiyonu
const getPreferredTranslation = (
    translations: { name: string, description: string | null, languageCode: string }[],
    languageCode: string
) => {
    const DEFAULT_LANG = 'tr';
    const FALLBACK_LANG = 'en';

    const t = translations.find(tr => tr.languageCode === languageCode) ||
        translations.find(tr => tr.languageCode === DEFAULT_LANG) ||
        translations.find(tr => tr.languageCode === FALLBACK_LANG);

    return {
        name: t?.name || 'N/A',
        description: t?.description || null
    };
};

/**
 * Mobil uygulamaya tutarlı bir API sağlamak için
 * veritabanı sonuçlarını standart bir { id, name } formatına dönüştürür.
 * (Tüm fonksiyonlar dile göre çalışacak şekilde güncellendi)
 */

// 1. Ekipmanları Getir (GÜNCELLENDİ - FALLBACK DİL DESTEĞİ)
export const getEquipmentService = async (languageCode: string) => {
    const languages = getLanguagesToTry(languageCode);

    const items = await prisma.workoutEquipment.findMany({
        select: {
            workoutEquipmentId: true,
            translations: {
                where: { languageCode: { in: languages } },
                select: { name: true, description: true, languageCode: true }
            }
        },
    });

    return items.map((item) => {
        const t = getPreferredTranslation(item.translations, languageCode);
        return {
            id: item.workoutEquipmentId,
            name: t.name,
            description: t.description,
        };
    }).sort((a, b) => a.name.localeCompare(b.name)); // Sıralamayı kod tarafında yap
};

// 2. Vücut Bölgelerini Getir (GÜNCELLENDİ - FALLBACK DİL DESTEĞİ)
export const getBodyPartsService = async (languageCode: string) => {
    const languages = getLanguagesToTry(languageCode);

    const items = await prisma.goalBodyPart.findMany({
        select: {
            goalBodyPartId: true,
            translations: {
                where: { languageCode: { in: languages } },
                select: { name: true, description: true, languageCode: true }
            }
        },
    });

    return items.map((item) => {
        const t = getPreferredTranslation(item.translations, languageCode);
        return {
            id: item.goalBodyPartId,
            name: t.name,
            description: t.description,
        };
    }).sort((a, b) => a.name.localeCompare(b.name));
};

// 3. Konumları Getir (GÜNCELLENDİ - FALLBACK DİL DESTEĞİ)
export const getLocationsService = async (languageCode: string) => {
    const languages = getLanguagesToTry(languageCode);

    const items = await prisma.workoutLocation.findMany({
        select: {
            workoutLocationId: true,
            translations: {
                where: { languageCode: { in: languages } },
                select: { name: true, description: true, languageCode: true }
            }
        },
    });

    return items.map((item) => {
        const t = getPreferredTranslation(item.translations, languageCode);
        return {
            id: item.workoutLocationId,
            name: t.name,
            description: t.description,
        };
    }).sort((a, b) => a.name.localeCompare(b.name));
};

// 4. Sağlık Kısıtlamalarını Getir (GÜNCELLENDİ - FALLBACK DİL DESTEĞİ)
export const getLimitationsService = async (languageCode: string) => {
    const languages = getLanguagesToTry(languageCode);

    const items = await prisma.healthLimitation.findMany({
        select: {
            healthLimitationId: true,
            translations: {
                where: { languageCode: { in: languages } },
                select: { name: true, description: true, languageCode: true }
            }
        },
    });

    return items.map((item) => {
        const t = getPreferredTranslation(item.translations, languageCode);
        return {
            id: item.healthLimitationId,
            name: t.name,
            description: t.description,
        };
    }).sort((a, b) => a.name.localeCompare(b.name));
};