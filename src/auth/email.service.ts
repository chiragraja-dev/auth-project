import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import * as nodemailer from 'nodemailer'
@Injectable()
export class EmailService {
    private readonly Logger = new Logger(EmailService.name);
    private transporter: nodemailer.Transporter;

    constructor(private readonly configService: ConfigService) {
        this.transporter = nodemailer.createTransport({
            host: this.configService.get<string>('SMTP_HOST') || 'smtp.gmail.com',
            port: this.configService.get<number>('SMTP_PORT') || 587,
            secure: false,
            auth: {
                user: this.configService.get<string>('SMTP_USER'),
                pass: this.configService.get<string>('SMTP_PASS'),
            },
        });
    }


    private getPasswordResetTemplate(resetUrl: string): string {
        return `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Password Reset</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #2c3e50;">Password Reset Request</h2>
                    <p>Hello,</p>
                    <p>We received a request to reset your password. If you made this request, please click the button below to reset your password:</p>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${resetUrl}" 
                           style="background-color: #3498db; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
                            Reset Password
                        </a>
                    </div>
                    
                    <p><strong>Important Security Information:</strong></p>
                    <ul>
                        <li>This link will expire in 1 hour for security reasons</li>
                        <li>If you didn't request this password reset, please ignore this email</li>
                        <li>Never share this link with anyone</li>
                        <li>Our support team will never ask for your password</li>
                    </ul>
                    
                    <p>If the button doesn't work, copy and paste this link into your browser:</p>
                    <p style="word-break: break-all; color: #7f8c8d;">${resetUrl}</p>
                    
                    <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
                    <p style="font-size: 12px; color: #7f8c8d;">
                        This is an automated email. Please do not reply to this message.
                    </p>
                </div>
            </body>
            </html>
        `;
    }
    async sendPasswordResetEmail(email: string, resetToken: string): Promise<boolean> {
        try {
            const resetUrl = `${this.configService.get<string>('FRONTEND_URL') || 'http://localhost:3000'}/reset-password?token=${resetToken}`;
            const mailOption = {
                from: `"${this.configService.get<string>('APP_NAME') || 'Your App'}" <${this.configService.get<string>('SMTP_FROM') || this.configService.get<string>('SMTP_USER')}>`,
                to: email,
                subject: 'Password Reset Request',
                html: this.getPasswordResetTemplate(resetUrl),
            };
            await this.transporter.sendMail(mailOption)
            this.Logger.log(`Password reset email sent to: ${email}`);
            return true
        } catch (error) {
            this.Logger.error(`Failed to send password reset email to ${email}:`, error);
            return false;
        }
    }
    private async generateOtp(length: number = 6): Promise<string> {
        const digits = '0123456789';
        let otp = '';
        for (let i = 0; i < length; i++) {
            otp += digits[Math.floor(Math.random() * 10)];
        }
        return otp;
    }

    private async getOtpEmailTemplate(otp: string, userName: string): Promise<string> {
        return `
    <div style="max-width: 600px; margin: auto; padding: 30px; background-color: #ffffff; border-radius: 10px; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);">
      <div style="text-align: center;">
        <h2 style="color: #2f80ed;">Verify Your Email</h2>
        <p style="font-size: 16px; color: #333;">Hello <strong>${userName}</strong>,</p>
        <p style="font-size: 15px; color: #555;">Please use the following One-Time Password (OTP) to verify your email address:</p>
        <div style="margin: 20px 0;">
          <span style="display: inline-block; font-size: 28px; font-weight: bold; letter-spacing: 8px; color: #2f80ed; background-color: #f0f4ff; padding: 12px 24px; border-radius: 8px;">${otp}</span>
        </div>
        <p style="font-size: 14px; color: #777;">This code will expire in <strong>10 minutes</strong>.</p>
        <p style="font-size: 14px; color: #999; margin-top: 30px;">If you didn't request this, you can safely ignore this email.</p>
      </div>
      <hr style="margin: 40px 0; border: none; border-top: 1px solid #eee;" />
      <div style="text-align: center; font-size: 13px; color: #aaa;">
        &copy; ${new Date().getFullYear()} YourApp. All rights reserved.
      </div>
    </div>
    `;
    }

    async sendOtpEmail(email: string, name: string, otp: string): Promise<boolean> {
        try {
            const mailOption = {
                from: `"${this.configService.get<string>('APP_NAME') || 'Your App'}" <${this.configService.get<string>('SMTP_FROM') || this.configService.get<string>('SMTP_USER')}>`,
                to: email,
                subject: 'Verify Your Email',
                html: (await (this.getOtpEmailTemplate(otp, name))).toString(),
            }
            this.transporter.sendMail(mailOption)
            this.Logger.log(`Password reset email sent to: ${email}`);
            return true

        } catch (error) {
            return false
        }
    }
}