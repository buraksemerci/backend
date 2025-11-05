// src/server.ts
import app from './app';
import { env } from './utils/env'; // <-- YENİ: Doğrulanmış ENV değişkenleri
import logger from './utils/logger'; // <-- YENİ: Logger

try {
    // 1. .env dosyasını doğrula. Eksikse, uygulama burada çöker.
    env;
    logger.info('Tüm çevre değişkenleri (environment variables) başarıyla doğrulandı.');

    // 2. Sunucuyu başlat
    const PORT = env.PORT;
    app.listen(PORT, () => {
        logger.info(`[Server]: Sunucu http://localhost:${PORT} adresinde çalışıyor`);
    });

} catch (error) {
    // Bu blok, Zod'un env doğrulamasının başarısız olması durumunda çalışır.
    logger.error(error, '.env doğrulaması başarısız oldu. Sunucu başlatılamıyor.');
    process.exit(1); // Hata ile çık
}