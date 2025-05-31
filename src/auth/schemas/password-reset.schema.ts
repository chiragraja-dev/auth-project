import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { Document } from 'mongoose';

@Schema({ timestamps: true, collection: "password_resets" })
export class PasswordReset extends Document {
    @Prop({ required: true })
    userId: string;

    @Prop({ required: true })
    tokenHash: string;

    @Prop({ required: true })
    expiresAt: Date;

    @Prop({ default: Date.now })
    createdAt: Date;
}
export const PasswordResetSchema = SchemaFactory.createForClass(PasswordReset);
