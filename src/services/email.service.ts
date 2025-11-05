// src/services/email.service.ts
import nodemailer from 'nodemailer';
import { env } from '../utils/env'; // <-- YENİ
import logger from '../utils/logger'; // <-- YENİ

// 1. .env değişkenlerini (doğrulanmış env'den) al
const EMAIL_HOST = env.EMAIL_HOST;
const EMAIL_PORT = env.EMAIL_PORT;
const EMAIL_USER = env.EMAIL_USER;
const EMAIL_PASS = env.EMAIL_PASS;
const EMAIL_FROM = env.EMAIL_FROM;

// 2. Transporter Nesnesini Oluştur
let transporter: nodemailer.Transporter;

if (EMAIL_HOST && EMAIL_USER && EMAIL_PASS && EMAIL_FROM) {
    transporter = nodemailer.createTransport({
        host: EMAIL_HOST,
        port: EMAIL_PORT,
        secure: EMAIL_PORT === 465,
        auth: {
            user: EMAIL_USER,
            pass: EMAIL_PASS,
        },
    });

    // Bağlantıyı test et
    transporter.verify((error, success) => {
        if (error) {
            logger.error(error, '[EmailService] UYARI: SMTP yapılandırması başarısız!');
        } else {
            logger.info('[EmailService]: Nodemailer (SMTP) servisi başarıyla yapılandırıldı.');
        }
    });

} else {
    logger.warn(
        '[EmailService] UYARI: EMAIL değişkenleri .env dosyasında eksik. E-posta gönderimi çalışmayacak.'
    );
}

/**
 * 6 haneli rastgele bir sayısal kod üretir.
 */
export const generateSixDigitCode = (): string => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

/**
 * Nodemailer (SMTP) kullanarak doğrulama kodu e-postası gönderir.
 */
export const sendVerificationCode = async (email: string, code: string) => {
    if (!transporter || !EMAIL_FROM) {
        logger.error('EmailService: Gönderim başarısız. Servis yapılandırılmamış.');
        throw new Error('E-posta servisi yapılandırılmamış.');
    }

    const mailOptions = {
        from: EMAIL_FROM,
        to: email,
        subject: 'MyFitMark Doğrulama Kodunuz',
        text: `Hesabınızı doğrulamak için kodunuz: ${code}`,
        html: `
      <div style="font-family: Arial, sans-serif; line-height: 1.6;">
        <h2>MyFitMark Hesabınızı Doğrulayın</h2>
        <p>Merhaba,</p>
        <p>Hesabınızı doğrulamak için lütfen aşağıdaki 6 haneli kodu kullanın. Bu kod 15 dakika geçerlidir.</p>
        <p style="font-size: 24px; font-weight: bold; letter-spacing: 2px;">
          ${code}
        </p>
        <p>Eğer bu isteği siz yapmadıysanız, bu e-postayı görmezden gelebilirsiniz.</p>
        <p>Teşekkürler,<br>MyFitMark Ekibi</p>
      </div>
    `,
    };

    try {
        logger.info(`[EmailService]: Doğrulama kodu gönderiliyor (Nodemailer ile): ${email}`);
        await transporter.sendMail(mailOptions);
        logger.info(`[EmailService]: E-posta başarıyla gönderildi: ${email}`);

    } catch (error: any) {
        logger.error(error, '[EmailService]: E-posta gönderim hatası');
        throw new Error('E-posta gönderilemedi.');
    }
};

/**
 * Nodemailer (SMTP) kullanarak şifre sıfırlama kodu e-postası gönderir.
 */
export const sendPasswordResetCode = async (email: string, code: string) => {
    if (!transporter || !EMAIL_FROM) {
        logger.error('EmailService: Gönderim başarısız. Servis yapılandırılmamış.');
        throw new Error('E-posta servisi yapılandırılmamış.');
    }

    const mailOptions = {
        from: EMAIL_FROM,
        to: email,
        subject: 'MyFitMark Şifre Sıfırlama Talebi',
        text: `Şifrenizi sıfırlamak için kodunuz: ${code}`,
        html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6;">
          <h2>MyFitMark Şifre Sıfırlama</h2>
          <p>Merhaba,</p>
          <p>Hesabınız için şifre sıfırlama talebinde bulundunuz. Lütfen aşağıdaki 6 haneli kodu kullanın. Bu kod 10 dakika geçerlidir.</p>
          <p style="font-size: 24px; font-weight: bold; letter-spacing: 2px;">
            ${code}
          </p>
          <p>Eğer bu isteği siz yapmadıysanız, bu e-postayı görmezden gelebilirsiniz.</p>
          <p>Teşekkürler,<br>MyFitMark Ekibi</p>
        </div>
      `,
    };

    try {
        logger.info(`[EmailService]: Şifre sıfırlama kodu gönderiliyor: ${email}`);
        await transporter.sendMail(mailOptions);
        logger.info(`[EmailService]: E-posta başarıyla gönderildi: ${email}`);
    } catch (error: any) {
        logger.error(error, '[EmailService]: E-posta gönderim hatası');
        throw new Error('E-posta gönderilemedi.');
    }
};