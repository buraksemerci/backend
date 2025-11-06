// Dosya: src/services/program.service.ts
import prisma from '../utils/prisma';
import { Prisma } from '@prisma/client';
import { ProfileCreationInput } from '../utils/zod.schemas';
import logger from '../utils/logger';

// --- (profile.service.ts'den kopyalanan YARDIMCI FONKSİYONLAR) ---
const DEFAULT_LANG = 'tr';
const FALLBACK_LANG = 'en';
const getLanguagesToTry = (languageCode: string) => {
    return [...new Set([languageCode, DEFAULT_LANG, FALLBACK_LANG])];
};
type Translation = { name: string; description?: string | null; languageCode: string };
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
// --- YARDIMCILAR SONU ---


/**
 * (MEVCUT FONKSİYON - auth.service.ts kullanır)
 * Kullanıcının girdilerine göre en uygun 'Genel Şablon' programını bulur.
 * @param tx Prisma Transaction Client
 * @param input Kullanıcının Zod'dan gelen tüm profil verisi
 * @returns Bulunan en iyi programın UUID'si veya null
 */
export const findBestTemplateProgram = async (
    tx: Prisma.TransactionClient,
    input: ProfileCreationInput,
): Promise<string | null> => {
    logger.info(`[ProgramService] Kullanıcı ${input.goal.goalTypeId} hedefi ve ${input.body.fitnessLevelId} seviyesi için program aranıyor...`);

    const program = await tx.workoutProgram.findFirst({
        where: {
            ownerUserId: null, // Sadece 'Genel Şablon'
            goalTypeId: input.goal.goalTypeId,
            fitnessLevelId: input.body.fitnessLevelId,
        },
        select: {
            workoutProgramId: true,
        },
    });

    if (!program) {
        logger.warn(`[ProgramService] Uygun şablon program bulunamadı. Fallback aranacak.`);
        return null;
    }

    logger.info(`[ProgramService] En uygun program bulundu: ${program.workoutProgramId}`);
    return program.workoutProgramId;
};

/**
 * (MEVCUT FONKSİYON - auth.service.ts kullanır)
 * Kullanıcının seçtiği günlere bir programı (veya dinlenmeyi) atar.
 */
export const assignInitialProgramToUser = async (
    tx: Prisma.TransactionClient,
    userId: string,
    input: ProfileCreationInput,
) => {
    const programId = await findBestTemplateProgram(tx, input);
    const daysToAssign = input.workoutDays;
    const allDaysOfWeek = [0, 1, 2, 3, 4, 5, 6];
    const assignments: Prisma.UserProgramAssignmentCreateManyInput[] = [];

    for (const day of allDaysOfWeek) {
        assignments.push({
            userId: userId,
            dayOfWeek: day,
            programId: daysToAssign.includes(day) ? programId : null,
            isRestDay: !daysToAssign.includes(day),
        });
    }

    await tx.userProgramAssignment.createMany({
        data: assignments,
    });
    logger.info(`[ProgramService] Kullanıcı ${userId} için 7 günlük program ataması tamamlandı.`);
};


// --- YENİ EKLENEN FONKSİYONLAR ---

/**
 * YENİ: Program Önizleme Servisi (Stateless)
 * "Kayıt öncesi" stratejiniz için program bulur ancak veritabanına YAZMAZ.
 */
export const generateProgramPreview = async (
    input: ProfileCreationInput,
    languageCode: string,
) => {
    const languages = getLanguagesToTry(languageCode);

    // 'findBestTemplateProgram' içindeki mantığı burada 'tx' olmadan kullanıyoruz
    // Not: prisma.$transaction olmadan, bu 'findFirst' ve 'findUnique'
    // iki ayrı veritabanı çağrısı olur, ancak bu bir önizleme olduğu için kabul edilebilir.

    logger.info(`[ProgramService] Önizleme için program aranıyor...`);
    const program = await prisma.workoutProgram.findFirst({
        where: {
            ownerUserId: null,
            goalTypeId: input.goal.goalTypeId,
            fitnessLevelId: input.body.fitnessLevelId,
        },
        select: {
            workoutProgramId: true,
            translations: {
                where: { languageCode: { in: languages } },
                select: { name: true, description: true, languageCode: true },
            },
        },
    });

    if (!program) {
        return null; // Kontrolcü (Controller) 404'e çevirecek
    }

    // Bulunan programın çevirisini formatla
    const t = getPreferredTranslation(program.translations, languageCode);

    return {
        programId: program.workoutProgramId,
        name: t.name,
        description: t.description,
        // Kullanıcının seçtiği günleri de geri döndürerek teyit et
        workoutDays: input.workoutDays,
    };
};

/**
 * YENİ: Tüm "Genel Şablon" programları listeler.
 */
export const getTemplatePrograms = async (languageCode: string) => {
    const languages = getLanguagesToTry(languageCode);

    const programs = await prisma.workoutProgram.findMany({
        where: {
            ownerUserId: null, // Sadece 'Genel Şablon' olanlar (Premium olmayan)
            deletedAt: null,   // Soft-delete edilenleri getirme
        },
        select: {
            workoutProgramId: true,
            difficultyLevel: true,
            // İlişkili ana verilerin çevirilerini de alabiliriz
            GoalType: { select: { translations: { where: { languageCode: { in: languages } } } } },
            FitnessLevel: { select: { translations: { where: { languageCode: { in: languages } } } } },
            translations: {
                where: { languageCode: { in: languages } },
                select: { name: true, description: true, languageCode: true },
            },
        },
    });

    // Gelen veriyi mobil uygulamanın seveceği temiz bir formata dönüştür
    return programs.map(p => {
        const t = getPreferredTranslation(p.translations, languageCode);

        return {
            id: p.workoutProgramId,
            name: t.name,
            description: t.description,
            difficultyLevel: p.difficultyLevel,
            goalType: getPreferredTranslation(p.GoalType?.translations || [], languageCode).name,
            fitnessLevel: getPreferredTranslation(p.FitnessLevel?.translations || [], languageCode).name,
        }
    });
};