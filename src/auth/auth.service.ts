import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Auth } from './schemas/auth.schemas';
import { Model } from 'mongoose'
import { JwtService } from '@nestjs/jwt';
import { SignupDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(Auth.name) private authModel: Model<Auth>,
        private jwtService: JwtService
    ) { }

    async signup(data: SignupDto): Promise<{ token: string, user: { email: string, name?: string } }> {
        const { email, name, password } = data
        if (!email || !name || !password) {
            new BadRequestException("Missing reuired fieild")
        }
        if (password.length >= 6) {
            new BadRequestException("Password must be at least 6 characters long.")
        }
        const user = await this.authModel.findOne({ email })
        if (user) {
            new BadRequestException("Email already exist.")
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
        return ({ user: userInfo, token: this.jwtService.sign({ id: _id, email: userInfo.email, name }) })
    }
}
