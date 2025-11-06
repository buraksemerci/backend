BEGIN TRY

BEGIN TRAN;

-- CreateTable
CREATE TABLE [dbo].[Gender] (
    [genderId] INT NOT NULL,
    [key] NVARCHAR(10) NOT NULL,
    CONSTRAINT [Gender_pkey] PRIMARY KEY CLUSTERED ([genderId]),
    CONSTRAINT [Gender_key_key] UNIQUE NONCLUSTERED ([key])
);

-- CreateTable
CREATE TABLE [dbo].[GoalType] (
    [goalTypeId] INT NOT NULL,
    [key] NVARCHAR(50) NOT NULL,
    CONSTRAINT [GoalType_pkey] PRIMARY KEY CLUSTERED ([goalTypeId]),
    CONSTRAINT [GoalType_key_key] UNIQUE NONCLUSTERED ([key])
);

-- CreateTable
CREATE TABLE [dbo].[BodyType] (
    [bodyTypeId] INT NOT NULL,
    [key] NVARCHAR(50) NOT NULL,
    CONSTRAINT [BodyType_pkey] PRIMARY KEY CLUSTERED ([bodyTypeId]),
    CONSTRAINT [BodyType_key_key] UNIQUE NONCLUSTERED ([key])
);

-- CreateTable
CREATE TABLE [dbo].[ActivityLevel] (
    [activityLevelId] INT NOT NULL,
    [key] NVARCHAR(50) NOT NULL,
    CONSTRAINT [ActivityLevel_pkey] PRIMARY KEY CLUSTERED ([activityLevelId]),
    CONSTRAINT [ActivityLevel_key_key] UNIQUE NONCLUSTERED ([key])
);

-- CreateTable
CREATE TABLE [dbo].[BodyTarget] (
    [bodyTargetId] INT NOT NULL,
    [key] NVARCHAR(50) NOT NULL,
    CONSTRAINT [BodyTarget_pkey] PRIMARY KEY CLUSTERED ([bodyTargetId]),
    CONSTRAINT [BodyTarget_key_key] UNIQUE NONCLUSTERED ([key])
);

-- CreateTable
CREATE TABLE [dbo].[WorkoutType] (
    [workoutTypeId] INT NOT NULL,
    [key] NVARCHAR(50) NOT NULL,
    CONSTRAINT [WorkoutType_pkey] PRIMARY KEY CLUSTERED ([workoutTypeId]),
    CONSTRAINT [WorkoutType_key_key] UNIQUE NONCLUSTERED ([key])
);

-- CreateTable
CREATE TABLE [dbo].[FitnessLevel] (
    [fitnessLevelId] INT NOT NULL,
    [key] NVARCHAR(50) NOT NULL,
    CONSTRAINT [FitnessLevel_pkey] PRIMARY KEY CLUSTERED ([fitnessLevelId]),
    CONSTRAINT [FitnessLevel_key_key] UNIQUE NONCLUSTERED ([key])
);

-- CreateTable
CREATE TABLE [dbo].[User] (
    [userId] UNIQUEIDENTIFIER NOT NULL,
    [username] NVARCHAR(100) NOT NULL,
    [email] NVARCHAR(255) NOT NULL,
    [isEmailVerified] BIT NOT NULL CONSTRAINT [User_isEmailVerified_df] DEFAULT 0,
    [createdAt] DATETIME2 NOT NULL CONSTRAINT [User_createdAt_df] DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT [User_pkey] PRIMARY KEY CLUSTERED ([userId]),
    CONSTRAINT [User_username_key] UNIQUE NONCLUSTERED ([username]),
    CONSTRAINT [User_email_key] UNIQUE NONCLUSTERED ([email])
);

-- CreateTable
CREATE TABLE [dbo].[UserLocalCredential] (
    [userId] UNIQUEIDENTIFIER NOT NULL,
    [passwordHash] NVARCHAR(max) NOT NULL,
    CONSTRAINT [UserLocalCredential_pkey] PRIMARY KEY CLUSTERED ([userId])
);

-- CreateTable
CREATE TABLE [dbo].[UserExternalLogin] (
    [id] INT NOT NULL IDENTITY(1,1),
    [loginProvider] NVARCHAR(50) NOT NULL,
    [providerKey] NVARCHAR(255) NOT NULL,
    [userId] UNIQUEIDENTIFIER NOT NULL,
    CONSTRAINT [UserExternalLogin_pkey] PRIMARY KEY CLUSTERED ([id]),
    CONSTRAINT [UserExternalLogin_loginProvider_providerKey_key] UNIQUE NONCLUSTERED ([loginProvider],[providerKey])
);

-- CreateTable
CREATE TABLE [dbo].[RefreshToken] (
    [refreshTokenId] INT NOT NULL IDENTITY(1,1),
    [tokenHash] NVARCHAR(256) NOT NULL,
    [deviceId] NVARCHAR(255) NOT NULL,
    [expiresAt] DATETIME2 NOT NULL,
    [isUsed] BIT NOT NULL CONSTRAINT [RefreshToken_isUsed_df] DEFAULT 0,
    [createdAt] DATETIME2 NOT NULL CONSTRAINT [RefreshToken_createdAt_df] DEFAULT CURRENT_TIMESTAMP,
    [createdByIP] NVARCHAR(45) NOT NULL,
    [userAgent] NVARCHAR(512) NOT NULL,
    [userId] UNIQUEIDENTIFIER NOT NULL,
    CONSTRAINT [RefreshToken_pkey] PRIMARY KEY CLUSTERED ([refreshTokenId]),
    CONSTRAINT [RefreshToken_tokenHash_key] UNIQUE NONCLUSTERED ([tokenHash]),
    CONSTRAINT [RefreshToken_userId_deviceId_key] UNIQUE NONCLUSTERED ([userId],[deviceId])
);

-- CreateTable
CREATE TABLE [dbo].[EmailVerificationToken] (
    [verificationTokenId] INT NOT NULL IDENTITY(1,1),
    [tokenHash] NVARCHAR(256) NOT NULL,
    [expiresAt] DATETIME2 NOT NULL,
    [isUsed] BIT NOT NULL CONSTRAINT [EmailVerificationToken_isUsed_df] DEFAULT 0,
    [lastSentAt] DATETIME2 NOT NULL CONSTRAINT [EmailVerificationToken_lastSentAt_df] DEFAULT CURRENT_TIMESTAMP,
    [sendCount] INT NOT NULL CONSTRAINT [EmailVerificationToken_sendCount_df] DEFAULT 1,
    [requestIP] NVARCHAR(45) NOT NULL,
    [userAgent] NVARCHAR(512) NOT NULL,
    [failedAttempts] INT NOT NULL CONSTRAINT [EmailVerificationToken_failedAttempts_df] DEFAULT 0,
    [userId] UNIQUEIDENTIFIER NOT NULL,
    CONSTRAINT [EmailVerificationToken_pkey] PRIMARY KEY CLUSTERED ([verificationTokenId])
);

-- CreateTable
CREATE TABLE [dbo].[PasswordResetToken] (
    [resetTokenId] INT NOT NULL IDENTITY(1,1),
    [tokenHash] NVARCHAR(256) NOT NULL,
    [expiresAt] DATETIME2 NOT NULL,
    [isUsed] BIT NOT NULL CONSTRAINT [PasswordResetToken_isUsed_df] DEFAULT 0,
    [lastSentAt] DATETIME2 NOT NULL CONSTRAINT [PasswordResetToken_lastSentAt_df] DEFAULT CURRENT_TIMESTAMP,
    [sendCount] INT NOT NULL CONSTRAINT [PasswordResetToken_sendCount_df] DEFAULT 1,
    [requestIP] NVARCHAR(45) NOT NULL,
    [userAgent] NVARCHAR(512) NOT NULL,
    [failedAttempts] INT NOT NULL CONSTRAINT [PasswordResetToken_failedAttempts_df] DEFAULT 0,
    [userId] UNIQUEIDENTIFIER NOT NULL,
    CONSTRAINT [PasswordResetToken_pkey] PRIMARY KEY CLUSTERED ([resetTokenId])
);

-- CreateTable
CREATE TABLE [dbo].[UserProfile] (
    [userId] UNIQUEIDENTIFIER NOT NULL,
    [firstName] NVARCHAR(100) NOT NULL,
    [lastName] NVARCHAR(100) NOT NULL,
    [birthDate] DATE NOT NULL,
    [genderId] INT,
    CONSTRAINT [UserProfile_pkey] PRIMARY KEY CLUSTERED ([userId])
);

-- CreateTable
CREATE TABLE [dbo].[UserBody] (
    [userId] UNIQUEIDENTIFIER NOT NULL,
    [heightCM] DECIMAL(5,2) NOT NULL,
    [weightKG] DECIMAL(5,2) NOT NULL,
    [activityLevelId] INT,
    [bodyTypeId] INT,
    [fitnessLevelId] INT,
    CONSTRAINT [UserBody_pkey] PRIMARY KEY CLUSTERED ([userId])
);

-- CreateTable
CREATE TABLE [dbo].[UserGoal] (
    [userId] UNIQUEIDENTIFIER NOT NULL,
    [targetWeightKG] DECIMAL(5,2),
    [goalTypeId] INT NOT NULL,
    CONSTRAINT [UserGoal_pkey] PRIMARY KEY CLUSTERED ([userId])
);

-- CreateTable
CREATE TABLE [dbo].[UserSetting] (
    [userId] UNIQUEIDENTIFIER NOT NULL,
    [preferredUnit] NVARCHAR(10) NOT NULL,
    [preferredLanguage] NVARCHAR(10) NOT NULL CONSTRAINT [UserSetting_preferredLanguage_df] DEFAULT 'tr',
    [theme] NVARCHAR(10) NOT NULL CONSTRAINT [UserSetting_theme_df] DEFAULT 'system',
    CONSTRAINT [UserSetting_pkey] PRIMARY KEY CLUSTERED ([userId])
);

-- CreateTable
CREATE TABLE [dbo].[UserProgramPreference] (
    [userId] UNIQUEIDENTIFIER NOT NULL,
    [workoutDuration] INT,
    [startWithWarmup] BIT NOT NULL CONSTRAINT [UserProgramPreference_startWithWarmup_df] DEFAULT 1,
    [createdAt] DATETIME2 NOT NULL CONSTRAINT [UserProgramPreference_createdAt_df] DEFAULT CURRENT_TIMESTAMP,
    [updatedAt] DATETIME2 NOT NULL,
    [workoutEquipmentId] UNIQUEIDENTIFIER,
    CONSTRAINT [UserProgramPreference_pkey] PRIMARY KEY CLUSTERED ([userId])
);

-- CreateTable
CREATE TABLE [dbo].[UserProgramAssignment] (
    [id] INT NOT NULL IDENTITY(1,1),
    [dayOfWeek] INT NOT NULL,
    [isRestDay] BIT NOT NULL CONSTRAINT [UserProgramAssignment_isRestDay_df] DEFAULT 0,
    [deletedAt] DATETIME2,
    [userId] UNIQUEIDENTIFIER NOT NULL,
    [programId] UNIQUEIDENTIFIER,
    CONSTRAINT [UserProgramAssignment_pkey] PRIMARY KEY CLUSTERED ([id]),
    CONSTRAINT [UserProgramAssignment_userId_dayOfWeek_key] UNIQUE NONCLUSTERED ([userId],[dayOfWeek])
);

-- CreateTable
CREATE TABLE [dbo].[UserChallengePlan] (
    [userChallengePlanId] INT NOT NULL IDENTITY(1,1),
    [progressDay] INT NOT NULL CONSTRAINT [UserChallengePlan_progressDay_df] DEFAULT 1,
    [status] NVARCHAR(50) NOT NULL,
    [startedAt] DATETIME2 NOT NULL CONSTRAINT [UserChallengePlan_startedAt_df] DEFAULT CURRENT_TIMESTAMP,
    [lastActivityAt] DATETIME2 NOT NULL,
    [createdAt] DATETIME2 NOT NULL CONSTRAINT [UserChallengePlan_createdAt_df] DEFAULT CURRENT_TIMESTAMP,
    [updatedAt] DATETIME2 NOT NULL,
    [deletedAt] DATETIME2,
    [userId] UNIQUEIDENTIFIER NOT NULL,
    [challengePlanId] UNIQUEIDENTIFIER NOT NULL,
    CONSTRAINT [UserChallengePlan_pkey] PRIMARY KEY CLUSTERED ([userChallengePlanId])
);

-- CreateTable
CREATE TABLE [dbo].[ContentAudience] (
    [id] INT NOT NULL IDENTITY(1,1),
    [contentType] NVARCHAR(1000) NOT NULL,
    [contentId] UNIQUEIDENTIFIER NOT NULL,
    [genderId] INT,
    [minAge] INT,
    [maxAge] INT,
    [fitnessLevelId] INT,
    CONSTRAINT [ContentAudience_pkey] PRIMARY KEY CLUSTERED ([id])
);

-- CreateTable
CREATE TABLE [dbo].[WorkoutProgram] (
    [workoutProgramId] UNIQUEIDENTIFIER NOT NULL,
    [difficultyLevel] INT NOT NULL,
    [createdAt] DATETIME2 NOT NULL CONSTRAINT [WorkoutProgram_createdAt_df] DEFAULT CURRENT_TIMESTAMP,
    [updatedAt] DATETIME2 NOT NULL,
    [deletedAt] DATETIME2,
    [ownerUserId] UNIQUEIDENTIFIER,
    [goalTypeId] INT,
    [bodyTargetId] INT,
    [fitnessLevelId] INT,
    CONSTRAINT [WorkoutProgram_pkey] PRIMARY KEY CLUSTERED ([workoutProgramId])
);

-- CreateTable
CREATE TABLE [dbo].[ChallengeWorkoutPlan] (
    [challengePlanId] UNIQUEIDENTIFIER NOT NULL,
    [durationDays] INT NOT NULL,
    [createdAt] DATETIME2 NOT NULL CONSTRAINT [ChallengeWorkoutPlan_createdAt_df] DEFAULT CURRENT_TIMESTAMP,
    [updatedAt] DATETIME2 NOT NULL,
    [fitnessLevelId] INT,
    CONSTRAINT [ChallengeWorkoutPlan_pkey] PRIMARY KEY CLUSTERED ([challengePlanId])
);

-- CreateTable
CREATE TABLE [dbo].[ChallengeWorkoutPlanDay] (
    [challengeWorkoutPlanDayId] UNIQUEIDENTIFIER NOT NULL,
    [dayNumber] INT NOT NULL,
    [isRestDay] BIT NOT NULL CONSTRAINT [ChallengeWorkoutPlanDay_isRestDay_df] DEFAULT 0,
    [createdAt] DATETIME2 NOT NULL CONSTRAINT [ChallengeWorkoutPlanDay_createdAt_df] DEFAULT CURRENT_TIMESTAMP,
    [updatedAt] DATETIME2 NOT NULL,
    [goalTypeId] INT,
    [bodyTargetId] INT,
    [challengePlanId] UNIQUEIDENTIFIER NOT NULL,
    CONSTRAINT [ChallengeWorkoutPlanDay_pkey] PRIMARY KEY CLUSTERED ([challengeWorkoutPlanDayId]),
    CONSTRAINT [ChallengeWorkoutPlanDay_challengePlanId_dayNumber_key] UNIQUE NONCLUSTERED ([challengePlanId],[dayNumber])
);

-- CreateTable
CREATE TABLE [dbo].[Workout] (
    [workoutId] UNIQUEIDENTIFIER NOT NULL,
    [effectivenessScore] DECIMAL(3,2),
    [metValue] DECIMAL(4,2),
    [workoutTypeId] INT NOT NULL,
    [workoutCategoryId] UNIQUEIDENTIFIER,
    [workoutEquipmentId] UNIQUEIDENTIFIER,
    CONSTRAINT [Workout_pkey] PRIMARY KEY CLUSTERED ([workoutId])
);

-- CreateTable
CREATE TABLE [dbo].[WorkoutCategory] (
    [workoutCategoryId] UNIQUEIDENTIFIER NOT NULL,
    [categoryKey] NVARCHAR(100) NOT NULL,
    [movementPattern] NVARCHAR(100),
    [isCompound] BIT NOT NULL CONSTRAINT [WorkoutCategory_isCompound_df] DEFAULT 0,
    CONSTRAINT [WorkoutCategory_pkey] PRIMARY KEY CLUSTERED ([workoutCategoryId]),
    CONSTRAINT [WorkoutCategory_categoryKey_key] UNIQUE NONCLUSTERED ([categoryKey])
);

-- CreateTable
CREATE TABLE [dbo].[WorkoutAsset] (
    [assetId] UNIQUEIDENTIFIER NOT NULL,
    [assetPhoto] NVARCHAR(max),
    [assetVideo] NVARCHAR(max),
    [genderId] INT NOT NULL CONSTRAINT [WorkoutAsset_genderId_df] DEFAULT 3,
    [workoutId] UNIQUEIDENTIFIER NOT NULL,
    CONSTRAINT [WorkoutAsset_pkey] PRIMARY KEY CLUSTERED ([assetId])
);

-- CreateTable
CREATE TABLE [dbo].[Muscle] (
    [muscleId] UNIQUEIDENTIFIER NOT NULL,
    CONSTRAINT [Muscle_pkey] PRIMARY KEY CLUSTERED ([muscleId])
);

-- CreateTable
CREATE TABLE [dbo].[HealthLimitation] (
    [healthLimitationId] UNIQUEIDENTIFIER NOT NULL,
    CONSTRAINT [HealthLimitation_pkey] PRIMARY KEY CLUSTERED ([healthLimitationId])
);

-- CreateTable
CREATE TABLE [dbo].[GoalBodyPart] (
    [goalBodyPartId] UNIQUEIDENTIFIER NOT NULL,
    CONSTRAINT [GoalBodyPart_pkey] PRIMARY KEY CLUSTERED ([goalBodyPartId])
);

-- CreateTable
CREATE TABLE [dbo].[WorkoutEquipment] (
    [workoutEquipmentId] UNIQUEIDENTIFIER NOT NULL,
    CONSTRAINT [WorkoutEquipment_pkey] PRIMARY KEY CLUSTERED ([workoutEquipmentId])
);

-- CreateTable
CREATE TABLE [dbo].[WorkoutLocation] (
    [workoutLocationId] UNIQUEIDENTIFIER NOT NULL,
    CONSTRAINT [WorkoutLocation_pkey] PRIMARY KEY CLUSTERED ([workoutLocationId])
);

-- CreateTable
CREATE TABLE [dbo].[GoalTypeTranslation] (
    [goalTypeId] INT NOT NULL,
    [languageCode] NVARCHAR(10) NOT NULL,
    [name] NVARCHAR(100) NOT NULL,
    [description] NVARCHAR(max),
    CONSTRAINT [GoalTypeTranslation_pkey] PRIMARY KEY CLUSTERED ([goalTypeId],[languageCode])
);

-- CreateTable
CREATE TABLE [dbo].[BodyTypeTranslation] (
    [bodyTypeId] INT NOT NULL,
    [languageCode] NVARCHAR(10) NOT NULL,
    [name] NVARCHAR(100) NOT NULL,
    [description] NVARCHAR(max),
    CONSTRAINT [BodyTypeTranslation_pkey] PRIMARY KEY CLUSTERED ([bodyTypeId],[languageCode])
);

-- CreateTable
CREATE TABLE [dbo].[ActivityLevelTranslation] (
    [activityLevelId] INT NOT NULL,
    [languageCode] NVARCHAR(10) NOT NULL,
    [name] NVARCHAR(100) NOT NULL,
    [description] NVARCHAR(max),
    CONSTRAINT [ActivityLevelTranslation_pkey] PRIMARY KEY CLUSTERED ([activityLevelId],[languageCode])
);

-- CreateTable
CREATE TABLE [dbo].[BodyTargetTranslation] (
    [bodyTargetId] INT NOT NULL,
    [languageCode] NVARCHAR(10) NOT NULL,
    [name] NVARCHAR(100) NOT NULL,
    [description] NVARCHAR(max),
    CONSTRAINT [BodyTargetTranslation_pkey] PRIMARY KEY CLUSTERED ([bodyTargetId],[languageCode])
);

-- CreateTable
CREATE TABLE [dbo].[WorkoutTypeTranslation] (
    [workoutTypeId] INT NOT NULL,
    [languageCode] NVARCHAR(10) NOT NULL,
    [name] NVARCHAR(100) NOT NULL,
    [description] NVARCHAR(max),
    CONSTRAINT [WorkoutTypeTranslation_pkey] PRIMARY KEY CLUSTERED ([workoutTypeId],[languageCode])
);

-- CreateTable
CREATE TABLE [dbo].[FitnessLevelTranslation] (
    [fitnessLevelId] INT NOT NULL,
    [languageCode] NVARCHAR(10) NOT NULL,
    [name] NVARCHAR(100) NOT NULL,
    [description] NVARCHAR(max),
    CONSTRAINT [FitnessLevelTranslation_pkey] PRIMARY KEY CLUSTERED ([fitnessLevelId],[languageCode])
);

-- CreateTable
CREATE TABLE [dbo].[WorkoutCategoryTranslation] (
    [workoutCategoryId] UNIQUEIDENTIFIER NOT NULL,
    [languageCode] NVARCHAR(10) NOT NULL,
    [name] NVARCHAR(100) NOT NULL,
    [description] NVARCHAR(max),
    CONSTRAINT [WorkoutCategoryTranslation_pkey] PRIMARY KEY CLUSTERED ([workoutCategoryId],[languageCode])
);

-- CreateTable
CREATE TABLE [dbo].[HealthLimitationTranslation] (
    [healthLimitationId] UNIQUEIDENTIFIER NOT NULL,
    [languageCode] NVARCHAR(10) NOT NULL,
    [name] NVARCHAR(100) NOT NULL,
    [description] NVARCHAR(max),
    CONSTRAINT [HealthLimitationTranslation_pkey] PRIMARY KEY CLUSTERED ([healthLimitationId],[languageCode])
);

-- CreateTable
CREATE TABLE [dbo].[GoalBodyPartTranslation] (
    [goalBodyPartId] UNIQUEIDENTIFIER NOT NULL,
    [languageCode] NVARCHAR(10) NOT NULL,
    [name] NVARCHAR(100) NOT NULL,
    [description] NVARCHAR(max),
    CONSTRAINT [GoalBodyPartTranslation_pkey] PRIMARY KEY CLUSTERED ([goalBodyPartId],[languageCode])
);

-- CreateTable
CREATE TABLE [dbo].[WorkoutEquipmentTranslation] (
    [workoutEquipmentId] UNIQUEIDENTIFIER NOT NULL,
    [languageCode] NVARCHAR(10) NOT NULL,
    [name] NVARCHAR(100) NOT NULL,
    [description] NVARCHAR(max),
    CONSTRAINT [WorkoutEquipmentTranslation_pkey] PRIMARY KEY CLUSTERED ([workoutEquipmentId],[languageCode])
);

-- CreateTable
CREATE TABLE [dbo].[WorkoutLocationTranslation] (
    [workoutLocationId] UNIQUEIDENTIFIER NOT NULL,
    [languageCode] NVARCHAR(10) NOT NULL,
    [name] NVARCHAR(100) NOT NULL,
    [description] NVARCHAR(max),
    CONSTRAINT [WorkoutLocationTranslation_pkey] PRIMARY KEY CLUSTERED ([workoutLocationId],[languageCode])
);

-- CreateTable
CREATE TABLE [dbo].[MuscleTranslation] (
    [muscleId] UNIQUEIDENTIFIER NOT NULL,
    [languageCode] NVARCHAR(10) NOT NULL,
    [name] NVARCHAR(100) NOT NULL,
    CONSTRAINT [MuscleTranslation_pkey] PRIMARY KEY CLUSTERED ([muscleId],[languageCode])
);

-- CreateTable
CREATE TABLE [dbo].[WorkoutTranslation] (
    [workoutId] UNIQUEIDENTIFIER NOT NULL,
    [languageCode] NVARCHAR(10) NOT NULL,
    [name] NVARCHAR(255) NOT NULL,
    [description] NVARCHAR(max),
    CONSTRAINT [WorkoutTranslation_pkey] PRIMARY KEY CLUSTERED ([workoutId],[languageCode])
);

-- CreateTable
CREATE TABLE [dbo].[WorkoutProgramTranslation] (
    [workoutProgramId] UNIQUEIDENTIFIER NOT NULL,
    [languageCode] NVARCHAR(10) NOT NULL,
    [name] NVARCHAR(255) NOT NULL,
    [description] NVARCHAR(max),
    CONSTRAINT [WorkoutProgramTranslation_pkey] PRIMARY KEY CLUSTERED ([workoutProgramId],[languageCode])
);

-- CreateTable
CREATE TABLE [dbo].[ChallengeWorkoutPlanTranslation] (
    [challengePlanId] UNIQUEIDENTIFIER NOT NULL,
    [languageCode] NVARCHAR(10) NOT NULL,
    [name] NVARCHAR(255) NOT NULL,
    [description] NVARCHAR(max),
    CONSTRAINT [ChallengeWorkoutPlanTranslation_pkey] PRIMARY KEY CLUSTERED ([challengePlanId],[languageCode])
);

-- CreateTable
CREATE TABLE [dbo].[ChallengeWorkoutPlanDayTranslation] (
    [challengeWorkoutPlanDayId] UNIQUEIDENTIFIER NOT NULL,
    [languageCode] NVARCHAR(10) NOT NULL,
    [name] NVARCHAR(255) NOT NULL,
    [description] NVARCHAR(max),
    CONSTRAINT [ChallengeWorkoutPlanDayTranslation_pkey] PRIMARY KEY CLUSTERED ([challengeWorkoutPlanDayId],[languageCode])
);

-- CreateTable
CREATE TABLE [dbo].[UserHealthLimitation] (
    [userId] UNIQUEIDENTIFIER NOT NULL,
    [healthLimitationId] UNIQUEIDENTIFIER NOT NULL,
    CONSTRAINT [UserHealthLimitation_pkey] PRIMARY KEY CLUSTERED ([userId],[healthLimitationId])
);

-- CreateTable
CREATE TABLE [dbo].[UserGoalPart] (
    [userId] UNIQUEIDENTIFIER NOT NULL,
    [goalBodyPartId] UNIQUEIDENTIFIER NOT NULL,
    CONSTRAINT [UserGoalPart_pkey] PRIMARY KEY CLUSTERED ([userId],[goalBodyPartId])
);

-- CreateTable
CREATE TABLE [dbo].[UserAvailableWorkoutEquipment] (
    [userId] UNIQUEIDENTIFIER NOT NULL,
    [workoutEquipmentId] UNIQUEIDENTIFIER NOT NULL,
    CONSTRAINT [UserAvailableWorkoutEquipment_pkey] PRIMARY KEY CLUSTERED ([userId],[workoutEquipmentId])
);

-- CreateTable
CREATE TABLE [dbo].[UserWorkoutLocation] (
    [userId] UNIQUEIDENTIFIER NOT NULL,
    [workoutLocationId] UNIQUEIDENTIFIER NOT NULL,
    CONSTRAINT [UserWorkoutLocation_pkey] PRIMARY KEY CLUSTERED ([userId],[workoutLocationId])
);

-- CreateTable
CREATE TABLE [dbo].[TargetMuscle] (
    [workoutId] UNIQUEIDENTIFIER NOT NULL,
    [muscleId] UNIQUEIDENTIFIER NOT NULL,
    [targetIntensity] INT,
    CONSTRAINT [TargetMuscle_pkey] PRIMARY KEY CLUSTERED ([workoutId],[muscleId])
);

-- CreateIndex
CREATE NONCLUSTERED INDEX [ContentAudience_contentType_contentId_idx] ON [dbo].[ContentAudience]([contentType], [contentId]);

-- AddForeignKey
ALTER TABLE [dbo].[UserLocalCredential] ADD CONSTRAINT [UserLocalCredential_userId_fkey] FOREIGN KEY ([userId]) REFERENCES [dbo].[User]([userId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserExternalLogin] ADD CONSTRAINT [UserExternalLogin_userId_fkey] FOREIGN KEY ([userId]) REFERENCES [dbo].[User]([userId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[RefreshToken] ADD CONSTRAINT [RefreshToken_userId_fkey] FOREIGN KEY ([userId]) REFERENCES [dbo].[User]([userId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[EmailVerificationToken] ADD CONSTRAINT [EmailVerificationToken_userId_fkey] FOREIGN KEY ([userId]) REFERENCES [dbo].[User]([userId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[PasswordResetToken] ADD CONSTRAINT [PasswordResetToken_userId_fkey] FOREIGN KEY ([userId]) REFERENCES [dbo].[User]([userId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserProfile] ADD CONSTRAINT [UserProfile_genderId_fkey] FOREIGN KEY ([genderId]) REFERENCES [dbo].[Gender]([genderId]) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserProfile] ADD CONSTRAINT [UserProfile_userId_fkey] FOREIGN KEY ([userId]) REFERENCES [dbo].[User]([userId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserBody] ADD CONSTRAINT [UserBody_activityLevelId_fkey] FOREIGN KEY ([activityLevelId]) REFERENCES [dbo].[ActivityLevel]([activityLevelId]) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserBody] ADD CONSTRAINT [UserBody_bodyTypeId_fkey] FOREIGN KEY ([bodyTypeId]) REFERENCES [dbo].[BodyType]([bodyTypeId]) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserBody] ADD CONSTRAINT [UserBody_fitnessLevelId_fkey] FOREIGN KEY ([fitnessLevelId]) REFERENCES [dbo].[FitnessLevel]([fitnessLevelId]) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserBody] ADD CONSTRAINT [UserBody_userId_fkey] FOREIGN KEY ([userId]) REFERENCES [dbo].[User]([userId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserGoal] ADD CONSTRAINT [UserGoal_goalTypeId_fkey] FOREIGN KEY ([goalTypeId]) REFERENCES [dbo].[GoalType]([goalTypeId]) ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserGoal] ADD CONSTRAINT [UserGoal_userId_fkey] FOREIGN KEY ([userId]) REFERENCES [dbo].[User]([userId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserSetting] ADD CONSTRAINT [UserSetting_userId_fkey] FOREIGN KEY ([userId]) REFERENCES [dbo].[User]([userId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserProgramPreference] ADD CONSTRAINT [UserProgramPreference_userId_fkey] FOREIGN KEY ([userId]) REFERENCES [dbo].[User]([userId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserProgramPreference] ADD CONSTRAINT [UserProgramPreference_workoutEquipmentId_fkey] FOREIGN KEY ([workoutEquipmentId]) REFERENCES [dbo].[WorkoutEquipment]([workoutEquipmentId]) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserProgramAssignment] ADD CONSTRAINT [UserProgramAssignment_userId_fkey] FOREIGN KEY ([userId]) REFERENCES [dbo].[User]([userId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserProgramAssignment] ADD CONSTRAINT [UserProgramAssignment_programId_fkey] FOREIGN KEY ([programId]) REFERENCES [dbo].[WorkoutProgram]([workoutProgramId]) ON DELETE SET NULL ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE [dbo].[UserChallengePlan] ADD CONSTRAINT [UserChallengePlan_userId_fkey] FOREIGN KEY ([userId]) REFERENCES [dbo].[User]([userId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserChallengePlan] ADD CONSTRAINT [UserChallengePlan_challengePlanId_fkey] FOREIGN KEY ([challengePlanId]) REFERENCES [dbo].[ChallengeWorkoutPlan]([challengePlanId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[ContentAudience] ADD CONSTRAINT [ContentAudience_genderId_fkey] FOREIGN KEY ([genderId]) REFERENCES [dbo].[Gender]([genderId]) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[ContentAudience] ADD CONSTRAINT [ContentAudience_fitnessLevelId_fkey] FOREIGN KEY ([fitnessLevelId]) REFERENCES [dbo].[FitnessLevel]([fitnessLevelId]) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[WorkoutProgram] ADD CONSTRAINT [WorkoutProgram_ownerUserId_fkey] FOREIGN KEY ([ownerUserId]) REFERENCES [dbo].[User]([userId]) ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE [dbo].[WorkoutProgram] ADD CONSTRAINT [WorkoutProgram_goalTypeId_fkey] FOREIGN KEY ([goalTypeId]) REFERENCES [dbo].[GoalType]([goalTypeId]) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[WorkoutProgram] ADD CONSTRAINT [WorkoutProgram_bodyTargetId_fkey] FOREIGN KEY ([bodyTargetId]) REFERENCES [dbo].[BodyTarget]([bodyTargetId]) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[WorkoutProgram] ADD CONSTRAINT [WorkoutProgram_fitnessLevelId_fkey] FOREIGN KEY ([fitnessLevelId]) REFERENCES [dbo].[FitnessLevel]([fitnessLevelId]) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[ChallengeWorkoutPlan] ADD CONSTRAINT [ChallengeWorkoutPlan_fitnessLevelId_fkey] FOREIGN KEY ([fitnessLevelId]) REFERENCES [dbo].[FitnessLevel]([fitnessLevelId]) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[ChallengeWorkoutPlanDay] ADD CONSTRAINT [ChallengeWorkoutPlanDay_goalTypeId_fkey] FOREIGN KEY ([goalTypeId]) REFERENCES [dbo].[GoalType]([goalTypeId]) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[ChallengeWorkoutPlanDay] ADD CONSTRAINT [ChallengeWorkoutPlanDay_bodyTargetId_fkey] FOREIGN KEY ([bodyTargetId]) REFERENCES [dbo].[BodyTarget]([bodyTargetId]) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[ChallengeWorkoutPlanDay] ADD CONSTRAINT [ChallengeWorkoutPlanDay_challengePlanId_fkey] FOREIGN KEY ([challengePlanId]) REFERENCES [dbo].[ChallengeWorkoutPlan]([challengePlanId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[Workout] ADD CONSTRAINT [Workout_workoutTypeId_fkey] FOREIGN KEY ([workoutTypeId]) REFERENCES [dbo].[WorkoutType]([workoutTypeId]) ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[Workout] ADD CONSTRAINT [Workout_workoutCategoryId_fkey] FOREIGN KEY ([workoutCategoryId]) REFERENCES [dbo].[WorkoutCategory]([workoutCategoryId]) ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE [dbo].[Workout] ADD CONSTRAINT [Workout_workoutEquipmentId_fkey] FOREIGN KEY ([workoutEquipmentId]) REFERENCES [dbo].[WorkoutEquipment]([workoutEquipmentId]) ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE [dbo].[WorkoutAsset] ADD CONSTRAINT [WorkoutAsset_genderId_fkey] FOREIGN KEY ([genderId]) REFERENCES [dbo].[Gender]([genderId]) ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[WorkoutAsset] ADD CONSTRAINT [WorkoutAsset_workoutId_fkey] FOREIGN KEY ([workoutId]) REFERENCES [dbo].[Workout]([workoutId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[GoalTypeTranslation] ADD CONSTRAINT [GoalTypeTranslation_goalTypeId_fkey] FOREIGN KEY ([goalTypeId]) REFERENCES [dbo].[GoalType]([goalTypeId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[BodyTypeTranslation] ADD CONSTRAINT [BodyTypeTranslation_bodyTypeId_fkey] FOREIGN KEY ([bodyTypeId]) REFERENCES [dbo].[BodyType]([bodyTypeId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[ActivityLevelTranslation] ADD CONSTRAINT [ActivityLevelTranslation_activityLevelId_fkey] FOREIGN KEY ([activityLevelId]) REFERENCES [dbo].[ActivityLevel]([activityLevelId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[BodyTargetTranslation] ADD CONSTRAINT [BodyTargetTranslation_bodyTargetId_fkey] FOREIGN KEY ([bodyTargetId]) REFERENCES [dbo].[BodyTarget]([bodyTargetId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[WorkoutTypeTranslation] ADD CONSTRAINT [WorkoutTypeTranslation_workoutTypeId_fkey] FOREIGN KEY ([workoutTypeId]) REFERENCES [dbo].[WorkoutType]([workoutTypeId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[FitnessLevelTranslation] ADD CONSTRAINT [FitnessLevelTranslation_fitnessLevelId_fkey] FOREIGN KEY ([fitnessLevelId]) REFERENCES [dbo].[FitnessLevel]([fitnessLevelId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[WorkoutCategoryTranslation] ADD CONSTRAINT [WorkoutCategoryTranslation_workoutCategoryId_fkey] FOREIGN KEY ([workoutCategoryId]) REFERENCES [dbo].[WorkoutCategory]([workoutCategoryId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[HealthLimitationTranslation] ADD CONSTRAINT [HealthLimitationTranslation_healthLimitationId_fkey] FOREIGN KEY ([healthLimitationId]) REFERENCES [dbo].[HealthLimitation]([healthLimitationId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[GoalBodyPartTranslation] ADD CONSTRAINT [GoalBodyPartTranslation_goalBodyPartId_fkey] FOREIGN KEY ([goalBodyPartId]) REFERENCES [dbo].[GoalBodyPart]([goalBodyPartId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[WorkoutEquipmentTranslation] ADD CONSTRAINT [WorkoutEquipmentTranslation_workoutEquipmentId_fkey] FOREIGN KEY ([workoutEquipmentId]) REFERENCES [dbo].[WorkoutEquipment]([workoutEquipmentId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[WorkoutLocationTranslation] ADD CONSTRAINT [WorkoutLocationTranslation_workoutLocationId_fkey] FOREIGN KEY ([workoutLocationId]) REFERENCES [dbo].[WorkoutLocation]([workoutLocationId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[MuscleTranslation] ADD CONSTRAINT [MuscleTranslation_muscleId_fkey] FOREIGN KEY ([muscleId]) REFERENCES [dbo].[Muscle]([muscleId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[WorkoutTranslation] ADD CONSTRAINT [WorkoutTranslation_workoutId_fkey] FOREIGN KEY ([workoutId]) REFERENCES [dbo].[Workout]([workoutId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[WorkoutProgramTranslation] ADD CONSTRAINT [WorkoutProgramTranslation_workoutProgramId_fkey] FOREIGN KEY ([workoutProgramId]) REFERENCES [dbo].[WorkoutProgram]([workoutProgramId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[ChallengeWorkoutPlanTranslation] ADD CONSTRAINT [ChallengeWorkoutPlanTranslation_challengePlanId_fkey] FOREIGN KEY ([challengePlanId]) REFERENCES [dbo].[ChallengeWorkoutPlan]([challengePlanId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[ChallengeWorkoutPlanDayTranslation] ADD CONSTRAINT [ChallengeWorkoutPlanDayTranslation_challengeWorkoutPlanDayId_fkey] FOREIGN KEY ([challengeWorkoutPlanDayId]) REFERENCES [dbo].[ChallengeWorkoutPlanDay]([challengeWorkoutPlanDayId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserHealthLimitation] ADD CONSTRAINT [UserHealthLimitation_userId_fkey] FOREIGN KEY ([userId]) REFERENCES [dbo].[User]([userId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserHealthLimitation] ADD CONSTRAINT [UserHealthLimitation_healthLimitationId_fkey] FOREIGN KEY ([healthLimitationId]) REFERENCES [dbo].[HealthLimitation]([healthLimitationId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserGoalPart] ADD CONSTRAINT [UserGoalPart_userId_fkey] FOREIGN KEY ([userId]) REFERENCES [dbo].[User]([userId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserGoalPart] ADD CONSTRAINT [UserGoalPart_goalBodyPartId_fkey] FOREIGN KEY ([goalBodyPartId]) REFERENCES [dbo].[GoalBodyPart]([goalBodyPartId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserAvailableWorkoutEquipment] ADD CONSTRAINT [UserAvailableWorkoutEquipment_userId_fkey] FOREIGN KEY ([userId]) REFERENCES [dbo].[User]([userId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserAvailableWorkoutEquipment] ADD CONSTRAINT [UserAvailableWorkoutEquipment_workoutEquipmentId_fkey] FOREIGN KEY ([workoutEquipmentId]) REFERENCES [dbo].[WorkoutEquipment]([workoutEquipmentId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserWorkoutLocation] ADD CONSTRAINT [UserWorkoutLocation_userId_fkey] FOREIGN KEY ([userId]) REFERENCES [dbo].[User]([userId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[UserWorkoutLocation] ADD CONSTRAINT [UserWorkoutLocation_workoutLocationId_fkey] FOREIGN KEY ([workoutLocationId]) REFERENCES [dbo].[WorkoutLocation]([workoutLocationId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[TargetMuscle] ADD CONSTRAINT [TargetMuscle_workoutId_fkey] FOREIGN KEY ([workoutId]) REFERENCES [dbo].[Workout]([workoutId]) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE [dbo].[TargetMuscle] ADD CONSTRAINT [TargetMuscle_muscleId_fkey] FOREIGN KEY ([muscleId]) REFERENCES [dbo].[Muscle]([muscleId]) ON DELETE CASCADE ON UPDATE CASCADE;

COMMIT TRAN;

END TRY
BEGIN CATCH

IF @@TRANCOUNT > 0
BEGIN
    ROLLBACK TRAN;
END;
THROW

END CATCH
