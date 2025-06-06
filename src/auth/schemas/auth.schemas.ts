import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { Document } from 'mongoose';

@Schema({ timestamps: true, collection: "auth_data" })
export class Auth extends Document {
    @Prop({ required: true, unique: true })
    email: string;

    @Prop()
    password?: string

    @Prop()
    googleId?: string;

    @Prop()
    githubId?: string;

    @Prop()
    name?: string

    @Prop({ default: false })
    isVerified: boolean;

    @Prop()
    otp?: string;

    @Prop()
    otpExpiresAt?: Date;
}

export const AuthSchema = SchemaFactory.createForClass(Auth);
