// Dosya: src/services/public.service.ts

import prisma from '../utils/prisma';

/**
 * Mobil uygulamaya tutarlı bir API sağlamak için
 * veritabanı sonuçlarını standart bir { id, name } formatına dönüştürür.
 * (Tüm fonksiyonlar dile göre çalışacak şekilde güncellendi)
 */

// 1. Ekipmanları Getir (GÜNCELLENDİ)
export const getEquipmentService = async (languageCode: string) => {
    const items = await prisma.workoutEquipmentTranslation.findMany({
        where: {
            languageCode: languageCode,
        },
        select: {
            workoutEquipmentId: true, // Ana ID
            name: true,
            description: true
        },
        orderBy: {
            name: 'asc', // Alfabetik sırala
        },
    });
    // workoutEquipmentId'yi 'id' olarak yeniden adlandır
    return items.map((item) => ({
        id: item.workoutEquipmentId,
        name: item.name,
        description: item.description,
    }));
};

// 2. Vücut Bölgelerini Getir (GÜNCELLENDİ)
export const getBodyPartsService = async (languageCode: string) => {
    const items = await prisma.goalBodyPartTranslation.findMany({
        where: {
            languageCode: languageCode,
        },
        select: {
            goalBodyPartId: true, // Ana ID
            name: true,
            description: true
        },
        orderBy: {
            name: 'asc',
        },
    });
    return items.map((item) => ({
        id: item.goalBodyPartId,
        name: item.name,
        description: item.description,
    }));
};

// 3. Konumları Getir (GÜNCELLENDİ)
export const getLocationsService = async (languageCode: string) => {
    const items = await prisma.workoutLocationTranslation.findMany({
        where: {
            languageCode: languageCode,
        },
        select: {
            workoutLocationId: true, // Ana ID
            name: true,
            description: true
        },
        orderBy: {
            name: 'asc',
        },
    });
    return items.map((item) => ({
        id: item.workoutLocationId,
        name: item.name,
        description: item.description,
    }));
};

// 4. Sağlık Kısıtlamalarını Getir (GÜNCELLENDİ)
export const getLimitationsService = async (languageCode: string) => {
    const items = await prisma.healthLimitationTranslation.findMany({
        where: {
            languageCode: languageCode,
        },
        select: {
            healthLimitationId: true, // Ana ID
            name: true,
            description: true
        },
        orderBy: {
            name: 'asc',
        },
    });
    return items.map((item) => ({
        id: item.healthLimitationId,
        name: item.name,
        description: item.description,
    }));
};