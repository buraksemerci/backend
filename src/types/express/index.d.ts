// JWT'mizin içine ne koyduğumuzu tanımlar
// (src/utils/jwt.utils.ts dosyasındaki signTokens fonksiyonuna göre)
interface JwtPayload {
    sub: string;
    isEmailVerified: boolean;
    // iat ve exp gibi standart alanlar otomatik olarak gelir
}

// Global Express namespace'ini genişlet
declare namespace Express {
    export interface Request {
        // req.user objesinin tipini tanımla
        // Artık 'any' değil ve 'JwtPayload' veya 'undefined' olabilir
        user?: JwtPayload;
    }
}