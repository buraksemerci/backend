// Dosya: src/services/schedule.service.ts
import prisma from '../utils/prisma';
import logger from '../utils/logger';
import { UpdateScheduleInput } from '../utils/zod.schemas';

/**
 * Kullanıcının 7 günlük takvim atamalarını, program detaylarıyla birlikte getirir.
 * @param userId Kullanıcının UUID'si
 */
export const getMyScheduleService = async (userId: string) => {
    logger.info(`[ScheduleService] ${userId} için takvim getiriliyor...`);

    const assignments = await prisma.userProgramAssignment.findMany({
        where: {
            userId: userId,
            deletedAt: null, // Soft-delete edilenleri getirme
        },
        select: {
            dayOfWeek: true,
            isRestDay: true,
            programId: true,
            Program: {
                // Atanmışsa, programın temel detaylarını da getir
                select: {
                    workoutProgramId: true,
                    // (Dil desteği için 'translations' ekleyebiliriz,
                    // ama şimdilik 'profile.service.ts' gibi karmaşıklaştırmayalım)
                    // Şimdilik sadece ana programın adını alıyoruz (çevirisiz)
                    // TODO: Bu alanı çevirili hale getir
                    translations: {
                        where: { languageCode: 'tr' }, // Varsayılan dil
                        select: { name: true }
                    }
                },
            },
        },
        orderBy: {
            dayOfWeek: 'asc', // 0'dan 6'ya sıralı
        },
    });

    // Veriyi mobil için formatla
    return assignments.map(a => ({
        dayOfWeek: a.dayOfWeek,
        isRestDay: a.isRestDay,
        programId: a.programId,
        programName: a.Program?.translations[0]?.name || null, // Çeviriden gelen adı ekle
    }));
};

/**
 * Kullanıcının 7 günlük takvimini atomik olarak günceller.
 * @param userId Kullanıcının UUID'si
 * @param assignments Zod'dan gelen 7 günlük yeni atama dizisi
 */
export const updateMyScheduleService = async (
    userId: string,
    assignments: UpdateScheduleInput['body']['assignments'],
) => {
    logger.info(`[ScheduleService] ${userId} için takvim güncelleniyor...`);

    // Atomik işlem: Önce tüm eski 7 günü sil, sonra yeni 7 günü ekle.
    // 'upsert' kullanmak döngüde 7 sorgu atar, bu yöntem 2 sorgu atar.

    await prisma.$transaction(async (tx) => {

        // 1. Kullanıcının mevcut tüm atamalarını sil
        // (Soft delete kullanıyorsak 'updateMany', yoksa 'deleteMany')
        await tx.userProgramAssignment.deleteMany({
            where: { userId: userId },
        });

        // (Eğer Soft Delete tercih edilirse, 'deleteMany' yerine bu kullanılır)
        // await tx.userProgramAssignment.updateMany({
        //   where: { userId: userId, deletedAt: null },
        //   data: { deletedAt: new Date() }
        // });

        // 2. Yeni 7 günü topluca oluştur
        await tx.userProgramAssignment.createMany({
            data: assignments.map(a => ({
                userId: userId,
                dayOfWeek: a.dayOfWeek,
                programId: a.isRestDay ? null : a.programId,
                isRestDay: a.isRestDay,
            })),
        });
    });

    logger.info(`[ScheduleService] ${userId} için takvim başarıyla güncellendi.`);
};