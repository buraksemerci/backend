// src/utils/logger.ts
import pino from 'pino';

// Geliştirme ortamında logları daha okunaklı hale getirmek için
// 'pino-pretty' kullanıp kullanmayacağımızı belirler.
const logger = pino({
    transport:
        process.env.NODE_ENV === 'development'
            ? {
                target: 'pino-pretty',
                options: {
                    colorize: true,
                    ignore: 'pid,hostname', // Gerekli olmayan bilgileri gizle
                    translateTime: 'SYS:dd-mm-yyyy HH:MM:ss', // Tarih formatı
                },
            }
            : undefined,
});

export default logger;