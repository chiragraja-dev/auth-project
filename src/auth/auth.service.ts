import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Auth } from './schemas/auth.schemas';
import { Model } from 'mongoose'
import { JwtService } from '@nestjs/jwt';
import { LoginDto, SignupDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(Auth.name) private authModel: Model<Auth>,
        private jwtService: JwtService
    ) { }

    private async userExits(email: string) {
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
        const user = await this.userExits(email)
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

    async signup(data: SignupDto): Promise<{ token: string, user: { email: string, name?: string } }> {
        const { email, name, password } = data
        if (!email || !name || !password) {
            throw new BadRequestException("Missing reuired fieild")
        }
        if (password.length < 6) {
            throw new BadRequestException("Password must be at least 6 characters long.")
        }
        const user = await this.userExits(email)
        if (user) {
            throw new BadRequestException("Email already exist.")
        }
        const hashedPassword = await bcrypt.hash(password, 10)
        const userData = new this.authModel({
            email,
            password: hashedPassword,
            name
        })
        await userData.save()
        const userObj = userData?.toObject();
        const { _id, googleId, password: _, ...userInfo } = userObj;
        return ({ user: userInfo, token: this.generateToken(_id, userInfo.email, userInfo.email) })
    }
}
