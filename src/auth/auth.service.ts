import { BadRequestException, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Auth } from './schemas/auth.schemas';
import { Model } from 'mongoose'
import { JwtService } from '@nestjs/jwt';
import { LoginDto, SignupDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { PasswordReset } from './schemas/password-reset.schema';
import { EmailService } from './email.service';

@Injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name);

    constructor(
        @InjectModel(Auth.name) private authModel: Model<Auth>,
        @InjectModel(PasswordReset.name) private PasswordResetModel: Model<PasswordReset>,
        private jwtService: JwtService,
        private emailService: EmailService
    ) { }

    async forgetPassword(email: string): Promise<{ success: boolean; message: string }> {
        try {
            const user = await this.authModel.findOne({ email }).exec();
            if (user) {
                const recentReset = await this.PasswordResetModel.findOne({
                    userId: user._id,
                    createdAt: { $gte: new Date(Date.now() - 1 * 60 * 1000) } // 15 minutes
                }).exec()

                if (recentReset) {
                    this.logger.warn(`Rate limit exceeded for password reset: ${email}`);
                    return {
                        success: true,
                        message: 'If your email is registered, you will receive password reset instructions.'
                    }
                }
                const resetToken = crypto.randomBytes(32).toString('hex');
                const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
                const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
                await this.PasswordResetModel.deleteMany({ userId: user._id });
                await this.PasswordResetModel.create({
                    userId: user._id,
                    tokenHash,
                    expiresAt
                })
                const emailSent = await this.emailService.sendPasswordResetEmail(email, resetToken);
                if (emailSent) {
                    this.logger.log(`Password reset token generated for user: ${user._id}`);
                } else {
                    this.logger.error(`Failed to send password reset email for user: ${user._id}`);
                }
            } else {
                this.logger.warn(`Password reset requested for non-existent email: ${email}`);
            }
            return {
                success: true,
                message: 'If your email is registered, you will receive password reset instructions.'
            }
        } catch (error) {
            this.logger.error('Error in forgetPassword:', error);
            return {
                success: true,
                message: 'If your email is registered, you will receive password reset instructions.'
            };
        }
    }

    async verifyResetToken(token: string): Promise<{ valid: boolean; userId?: string }> {
        try {
            const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

            const resetRecord = await this.PasswordResetModel.findOne({
                tokenHash,
                expiresAt: { $gt: new Date() }
            }).exec()

            if (resetRecord) {
                return { valid: true, userId: resetRecord.userId };
            }
            return { valid: false };
        } catch (error) {
            this.logger.error('Error verifying reset token:', error);
            return { valid: false };
        }
    }

    async resetPassword(token: string, newPassword: string): Promise<{ success: boolean; message: string }> {
        const { valid, userId } = await this.verifyResetToken(token)

        if (!valid || !userId) {
            return { success: false, message: 'Invalid or expired token' };
        }

        const user = await this.authModel.findById(userId)
        if (!user) {
            return { success: false, message: 'User not found' };
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        await user.save()
        await this.PasswordResetModel.deleteOne({ userId });
        return { success: true, message: 'Password has been reset successfully' };

    }

    async cleanupExpiredTokens(): Promise<void> {
        try {
            const result = await this.PasswordResetModel
                .deleteMany({ expiresAt: { $lt: new Date() } })
                .exec();

            if (result.deletedCount > 0) {
                this.logger.log(`Cleaned up ${result.deletedCount} expired reset tokens`);
            }
        } catch (error) {
            this.logger.error('Error cleaning up expired tokens:', error);
        }
    }

    private async userExists(email: string) {
        const user = await this.authModel.findOne({ email }).exec();
        return user
    }

    private generateToken(id: unknown, email: string, name: string) {
        return this.jwtService.sign({ id, email, name })
    }

    async login(data: LoginDto): Promise<{ token: string, user: { email: string, name?: string } }> {
        const { email, password } = data;
        if (!email || !password) {
            throw new BadRequestException("Missing reuired fieild")
        }
        const user = await this.userExists(email)
        if (!user) {
            throw new BadRequestException("Email Not exist.")
        }
        if (await bcrypt.compare(password, user?.password ?? "")) {
            throw new UnauthorizedException("Incorrect password")
        }

        const { _id, email: savedEmail, name: savedName } = user.toObject();
        return {
            token: this.generateToken(_id, savedEmail, savedName ?? ""),
            user: { email: savedEmail, name: savedName },
        };
    }

    generateOtp(): string {
        return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
    }

    async verifyOtp(email: string, otp: string): Promise<{ token: string, email: string, name: string }> {
        const user = await this.authModel.findOne({ email });
        if (!user) {
            throw new BadRequestException("User not found.");
        }
        if (user?.isVerified) {
            throw new BadRequestException("User already verified.");
        }
        if (user.otp !== otp || user?.otpExpiresAt && (new Date() > new Date(user?.otpExpiresAt))) {
            throw new BadRequestException("Invalid or expired OTP.");
        }

        user.isVerified = true;
        user.otp = undefined;
        user.otpExpiresAt = undefined;
        await user.save();

        const token = this.generateToken(user._id, user.email, user.name ?? "")
        return { token, email: user.email, name: user.name ?? "" };
    }

    async signup(data: SignupDto): Promise<{ message: string, email: string, name: string }> {
        try {

            const { email, name, password } = data
            if (!email || !name || !password) {
                throw new BadRequestException("Missing reuired fieild")
            }
            if (password.length < 6) {
                throw new BadRequestException("Password must be at least 6 characters long.")
            }
            const user = await this.userExists(email)
            if (user) {
                throw new BadRequestException("Email already exist.")
            }
            const hashedPassword = await bcrypt.hash(password, 10)
            const otp = this.generateOtp();

            const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000);

            const userData = new this.authModel({
                email,
                password: hashedPassword,
                name,
                otp,
                otpExpiresAt,
                isVerified: false,
            })
            await userData.save()
            await this.emailService.sendOtpEmail(email, name, otp)
            return { message: 'Signup successful. OTP sent to your email.', email, name };
        } catch (error) {
            console.log(error.message)
            return { message: error.message, email: "", name: "" };

        }
    }




    async loginWithGoogle(data: any): Promise<{ token: string, user: { email: string, name?: string } }> {
        const { email, googleId, name } = data;
        let user = await this.userExists(email)
        if (!user) {
            user = new this.authModel({
                email,
                googleId,
                name
            })
            await user.save()
        } else {
            if (!user.googleId && googleId) {
                user.googleId = googleId;
                await user.save();
            }
        }
        return {
            token: this.generateToken(user._id, email, name),
            user: { email, name }
        }
    }

    async loginWithGithub(data: any): Promise<{ token: string, user: { email: string, name?: string } }> {
        const { email, name, githubId } = data;
        let user = await this.userExists(email)
        if (!user) {
            user = new this.authModel({
                email,
                name,
                githubId
            })
            await user.save()
        } else {
            if (!user.githubId && githubId) {
                user.githubId = githubId
                await user.save()
            }
        }
        return {
            token: this.generateToken(user._id, email, name),
            user: { email, name }
        }
    }

}
