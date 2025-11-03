import jwt from 'jsonwebtoken';

// .env dosyanıza bir JWT_SECRET eklediğinizden emin olun!
const JWT_SECRET = process.env.JWT_SECRET || 'varsayilan-cok-gizli-anahtar-degistirin';
const ACCESS_TOKEN_EXPIRY = '15m'; // 15 dakika
const REFRESH_TOKEN_EXPIRY = '30d'; // 30 gün

// Token imzalama (Yeni token oluşturma)
export const signTokens = async (userId: string, isEmailVerified: boolean) => {
    // 1. Access Token Oluştur
    const accessToken = jwt.sign(
        { sub: userId, isEmailVerified },
        JWT_SECRET,
        { expiresIn: ACCESS_TOKEN_EXPIRY }
    );

    // 2. Refresh Token Oluştur
    const refreshToken = jwt.sign(
        { sub: userId }, // Refresh token'a ekstra bilgi koymayın
        JWT_SECRET, // (İdealde refresh token için ayrı bir secret kullanılır)
        { expiresIn: REFRESH_TOKEN_EXPIRY }
    );

    return { accessToken, refreshToken };
};

// TODO: Token doğrulama (verify) fonksiyonları eklenecek