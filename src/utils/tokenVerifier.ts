// Dosya: src/utils/tokenVerifier.ts
import { OAuth2Client } from 'google-auth-library';
import { env } from './env';
import logger from './logger';

// 1. Get your Google Client ID (from validated env)
const GOOGLE_CLIENT_ID = env.GOOGLE_CLIENT_ID;

if (!GOOGLE_CLIENT_ID) {
    // This will never run thanks to env.ts, but remains as a safeguard
    logger.warn(
        '[TokenVerifier] WARNING: GOOGLE_CLIENT_ID is missing in .env. Google verification will not work.'
    );
}

// 2. Initialize Google's OAuth2 client with this ID
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

/**
 * Verifies a Google ID Token and returns its payload.
 * @param {string} token - The idToken from the mobile app
 * @returns {Promise<{ email: string, externalId: string, emailVerified: boolean }>}
 * @throws {Error} - If the token is invalid or cannot be verified
 */
export const verifyGoogleToken = async (token: string) => {
    try {
        // 3. Verify the token against Google's servers
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: GOOGLE_CLIENT_ID, // Confirm the token was meant for us
        });

        const payload = ticket.getPayload();

        if (!payload) {
            throw new Error('Invalid token payload.');
        }

        // 4. Extract the info we need
        const email = payload.email;
        const externalId = payload.sub; // This is the user's unique ID at Google
        const emailVerified = payload.email_verified;

        if (!email || !externalId) {
            throw new Error('Token payload does not contain required info (email or sub).');
        }

        return {
            email,
            externalId,
            emailVerified: emailVerified || false, // Should come as 'true' from Google
        };

    } catch (error) {
        logger.error(error, '[TokenVerifier] Google token verification error:');
        // Re-throw the error to be caught by the controller
        throw new Error('TOKEN_VERIFICATION_FAILED');
    }
};