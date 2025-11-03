import prisma from '../utils/prisma';

/**
 * Mobil uygulamaya tutarlı bir API sağlamak için
 * veritabanı sonuçlarını standart bir { id, name } formatına dönüştürür.
 */

// 1. Ekipmanları Getir
export const getEquipmentService = async () => {
    const items = await prisma.workoutEquipment.findMany({
        select: {
            workoutEquipmentId: true,
            name: true,
        },
        orderBy: {
            name: 'asc', // Alfabetik sırala
        },
    });
    // workoutEquipmentId'yi 'id' olarak yeniden adlandır
    return items.map((item) => ({
        id: item.workoutEquipmentId,
        name: item.name,
    }));
};

// 2. Vücut Bölgelerini Getir
export const getBodyPartsService = async () => {
    const items = await prisma.goalBodyPart.findMany({
        select: {
            goalBodyPartId: true,
            name: true,
        },
        orderBy: {
            name: 'asc',
        },
    });
    return items.map((item) => ({
        id: item.goalBodyPartId,
        name: item.name,
    }));
};

// 3. Konumları Getir
export const getLocationsService = async () => {
    const items = await prisma.workoutLocation.findMany({
        select: {
            workoutLocationId: true,
            name: true,
        },
        orderBy: {
            name: 'asc',
        },
    });
    return items.map((item) => ({
        id: item.workoutLocationId,
        name: item.name,
    }));
};

// 4. Sağlık Kısıtlamalarını Getir
export const getLimitationsService = async () => {
    const items = await prisma.healthLimitation.findMany({
        select: {
            healthLimitationId: true,
            name: true,
        },
        orderBy: {
            name: 'asc',
        },
    });
    return items.map((item) => ({
        id: item.healthLimitationId,
        name: item.name,
    }));
};
