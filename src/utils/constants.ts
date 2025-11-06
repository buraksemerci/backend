// Dosya: src/utils/constants.ts

// Veritabanına manuel olarak eklediğiniz/ekleyeceğiniz Gender ID'leri ile eşleşmeli
export const GENDER_IDS = {
    MALE: 1,
    FEMALE: 2,
    ALL: 3, // (Bizim 'all' olarak tartıştığımız, 'herkes' için)
    UNKNOWN: 4 // (Analiz 2e: Kullanıcının cinsiyet belirtmek istemediği durum)
} as const;

// Analiz 3b: ContentAudience tablosunda içerik tiplerini ayırt etmek için
export const CONTENT_TYPES = {
    PROGRAM: 'WorkoutProgram',
    CHALLENGE: 'ChallengeWorkoutPlan',
    LIMITATION: 'HealthLimitation',
    BODY_PART: 'GoalBodyPart',
    WORKOUT: 'Workout',
    //... eklenebilir
} as const;

// Diğer sabitler (örn. Fitness Seviyeleri) buraya eklenebilir
// export const FITNESS_LEVEL_IDS = {
//   BEGINNER: 1,
//   INTERMEDIATE: 2,
//   ADVANCED: 3
// } as const;