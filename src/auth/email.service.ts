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
}