// src/utils/tokenVerifier.ts
import { OAuth2Client } from 'google-auth-library';
import { env } from './env'; // <-- YENİ
import logger from './logger'; // <-- YENİ

// 1. Google Client ID'nizi (doğrulanmış env'den) alın
const GOOGLE_CLIENT_ID = env.GOOGLE_CLIENT_ID;

if (!GOOGLE_CLIENT_ID) {
    // Bu aslında env.ts sayesinde hiç çalışmayacak, ama önlem olarak kalsın
    logger.warn(
        '[TokenVerifier] UYARI: GOOGLE_CLIENT_ID .env dosyasında eksik. Google ile doğrulama çalışmayacak.'
    );
}

// 2. Google'ın OAuth2 istemcisini bu ID ile başlatın
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

/**
 * Bir Google ID Token'ını doğrular ve payload'ını döndürür.
 * @param {string} token - Mobil uygulamadan gelen idToken
 * @returns {Promise<{ email: string, externalId: string, emailVerified: boolean }>}
 * @throws {Error} - Token geçersizse veya doğrulanamazsa
 */
export const verifyGoogleToken = async (token: string) => {
    try {
        // 3. Token'ı Google'ın sunucularına karşı doğrula
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: GOOGLE_CLIENT_ID, // Token'ın bizim için üretildiğini onayla
        });

        const payload = ticket.getPayload();

        if (!payload) {
            throw new Error('Geçersiz token payload.');
        }

        // 4. İhtiyacımız olan bilgileri ayıkla
        const email = payload.email;
        const externalId = payload.sub; // Bu, kullanıcının Google'daki unique ID'sidir
        const emailVerified = payload.email_verified;

        if (!email || !externalId) {
            throw new Error('Token payload gerekli bilgileri içermiyor (email veya sub).');
        }

        return {
            email,
            externalId,
            emailVerified: emailVerified || false, // Google'dan 'true' gelmeli
        };

    } catch (error) {
        logger.error(error, '[TokenVerifier] Google token doğrulama hatası:'); // <-- DEĞİŞTİ
        // Hatanın controller tarafından yakalanabilmesi için fırlat
        throw new Error('TOKEN_VERIFICATION_FAILED');
    }
};