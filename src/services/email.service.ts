// Dosya: src/services/email.service.ts
import nodemailer from 'nodemailer';
import { env } from '../utils/env';
import logger from '../utils/logger';

// 1. Get .env variables (from validated env)
const EMAIL_HOST = env.EMAIL_HOST;
const EMAIL_PORT = env.EMAIL_PORT;
const EMAIL_USER = env.EMAIL_USER;
const EMAIL_PASS = env.EMAIL_PASS;
const EMAIL_FROM = env.EMAIL_FROM;

// 2. Create Transporter Object
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

    // Test connection
    transporter.verify((error, success) => {
        if (error) {
            logger.error(error, '[EmailService] WARNING: SMTP configuration failed!');
        } else {
            logger.info('[EmailService]: Nodemailer (SMTP) service configured successfully.');
        }
    });

} else {
    logger.warn(
        '[EmailService] WARNING: EMAIL variables are missing in .env file. Email sending will not work.'
    );
}

/**
 * Generates a random 6-digit numeric code.
 */
export const generateSixDigitCode = (): string => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

/**
 * Sends a verification code email using Nodemailer (SMTP).
 */
export const sendVerificationCode = async (email: string, code: string) => {
    if (!transporter || !EMAIL_FROM) {
        logger.error('EmailService: Sending failed. Service not configured.');
        throw new Error('EMAIL_SERVICE_NOT_CONFIGURED');
    }

    const mailOptions = {
        from: EMAIL_FROM,
        to: email,
        subject: 'Your MyFitMark Verification Code',
        text: `Your code to verify your account is: ${code}`,
        html: `
      <div style="font-family: Arial, sans-serif; line-height: 1.6;">
        <h2>Verify Your MyFitMark Account</h2>
        <p>Hello,</p>
        <p>Please use the following 6-digit code to verify your account. This code is valid for 15 minutes.</p>
        <p style="font-size: 24px; font-weight: bold; letter-spacing: 2px;">
          ${code}
        </p>
        <p>If you did not request this, you can safely ignore this email.</p>
        <p>Thanks,<br>The MyFitMark Team</p>
      </div>
    `,
    };

    try {
        logger.info(`[EmailService]: Sending verification code (via Nodemailer): ${email}`);
        await transporter.sendMail(mailOptions);
        logger.info(`[EmailService]: Email sent successfully: ${email}`);

    } catch (error: any) {
        logger.error(error, '[EmailService]: Email sending error');
        throw new Error('EMAIL_SEND_FAILED');
    }
};

/**
 * Sends a password reset code email using Nodemailer (SMTP).
 */
export const sendPasswordResetCode = async (email: string, code: string) => {
    if (!transporter || !EMAIL_FROM) {
        logger.error('EmailService: Sending failed. Service not configured.');
        throw new Error('EMAIL_SERVICE_NOT_CONFIGURED');
    }

    const mailOptions = {
        from: EMAIL_FROM,
        to: email,
        subject: 'MyFitMark Password Reset Request',
        text: `Your code to reset your password is: ${code}`,
        html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6;">
          <h2>MyFitMark Password Reset</h2>
          <p>Hello,</p>
          <p>You requested a password reset for your account. Please use the following 6-digit code. This code is valid for 10 minutes.</p>
          <p style="font-size: 24px; font-weight: bold; letter-spacing: 2px;">
            ${code}
          </p>
          <p>If you did not request this, you can safely ignore this email.</p>
          <p>Thanks,<br>The MyFitMark Team</p>
        </div>
      `,
    };

    try {
        logger.info(`[EmailService]: Sending password reset code: ${email}`);
        await transporter.sendMail(mailOptions);
        logger.info(`[EmailService]: Email sent successfully: ${email}`);
    } catch (error: any) {
        logger.error(error, '[EmailService]: Email sending error');
        throw new Error('EMAIL_SEND_FAILED');
    }
};