import nodemailer from 'nodemailer';

// 1. .env değişkenlerini al
const EMAIL_HOST = process.env.EMAIL_HOST;
const EMAIL_PORT = parseInt(process.env.EMAIL_PORT || '587', 10);
const EMAIL_USER = process.env.EMAIL_USER; // SendGrid için bu "apikey" olmalı
const EMAIL_PASS = process.env.EMAIL_PASS; // SendGrid için bu SG.XXXX... anahtarı
const EMAIL_FROM = process.env.EMAIL_FROM; // Sizin: "MyFitMark_Deneme <kburaksemerci@hotmail.com>"

// 2. Transporter Nesnesini Oluştur
// Bu nesne, Nodemailer'a SendGrid'in SMTP sunucusuna nasıl bağlanacağını söyler.
let transporter: nodemailer.Transporter;

if (EMAIL_HOST && EMAIL_USER && EMAIL_PASS && EMAIL_FROM) {
    transporter = nodemailer.createTransport({
        host: EMAIL_HOST,
        port: EMAIL_PORT,
        secure: EMAIL_PORT === 465, // Port 465 ise true, 587 (bizimki) ise false
        auth: {
            user: EMAIL_USER,
            pass: EMAIL_PASS,
        },
        tls: {
            // SendGrid ile 587 portunda sorun yaşarsanız bunu zorunlu kılın
            // ciphers: 'SSLv3' 
        }
    });

    // Bağlantıyı test et (isteğe bağlı ama önerilir)
    transporter.verify((error, success) => {
        if (error) {
            console.error('[EmailService] UYARI: SMTP yapılandırması başarısız!', error.message);
        } else {
            console.log('[EmailService]: Nodemailer (SMTP) servisi başarıyla yapılandırıldı.');
        }
    });

} else {
    console.warn(
        '[EmailService] UYARI: EMAIL_HOST, EMAIL_USER, EMAIL_PASS veya EMAIL_FROM .env dosyasında eksik. E-posta gönderimi çalışmayacak.'
    );
}

/**
 * 6 haneli rastgele bir sayısal kod üretir.
 * (Bu fonksiyon aynı kalır)
 */
export const generateSixDigitCode = (): string => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

/**
 * Nodemailer (SMTP) kullanarak doğrulama kodu e-postası gönderir.
 * @param {string} email Alıcı e-posta adresi
 * @param {string} code Gönderilecek 6 haneli kod
 */
export const sendVerificationCode = async (email: string, code: string) => {
    // 3. Gönderimden önce transporter'ın var olup olmadığını kontrol et
    if (!transporter || !EMAIL_FROM) {
        console.error('EmailService: Gönderim başarısız. Servis yapılandırılmamış.');
        throw new Error('E-posta servisi yapılandırılmamış.');
    }

    // 4. E-posta şablonunu oluştur (Nodemailer formatı)
    const mailOptions = {
        from: EMAIL_FROM, // .env'den gelen: "MyFitMark_Deneme <kburaksemerci@hotmail.com>"
        to: email,
        subject: 'MyFitMark Doğrulama Kodunuz', // Şirket isminizi ekledim
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
        // 5. E-postayı gönder
        console.log(`[EmailService]: Doğrulama kodu gönderiliyor (Nodemailer ile): ${email}`);
        await transporter.sendMail(mailOptions);
        console.log(`[EmailService]: E-posta başarıyla gönderildi.`);

    } catch (error: any) {
        console.error('[EmailService]: E-posta gönderim hatası:', error);

        // Hata fırlat ki auth.service.ts'deki Prisma transaction'ı geri alınsın
        throw new Error('E-posta gönderilemedi.');
    }
};
/**
 * Nodemailer (SMTP) kullanarak şifre sıfırlama kodu e-postası gönderir.
 * @param {string} email Alıcı e-posta adresi
 * @param {string} code Gönderilecek 6 haneli kod
 */
export const sendPasswordResetCode = async (email: string, code: string) => {
    if (!transporter || !EMAIL_FROM) {
        console.error('EmailService: Gönderim başarısız. Servis yapılandırılmamış.');
        throw new Error('E-posta servisi yapılandırılmamış.');
    }

    // E-posta şablonunu oluştur
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
        console.log(`[EmailService]: Şifre sıfırlama kodu gönderiliyor: ${email}`);
        await transporter.sendMail(mailOptions);
        console.log(`[EmailService]: E-posta başarıyla gönderildi.`);
    } catch (error: any) {
        console.error('[EmailService]: E-posta gönderim hatası:', error);
        throw new Error('E-posta gönderilemedi.');
    }
};