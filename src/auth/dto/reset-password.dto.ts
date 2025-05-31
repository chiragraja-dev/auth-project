import { IsEmail, IsNotEmpty } from "class-validator";
import { IsString, MinLength } from 'class-validator';

export class ForgetPasswordDto {
    @IsEmail({}, { message: 'Please provide a valid email address' })
    @IsNotEmpty({ message: 'Email is required' })
    email: string;
}


export class ResetPasswordDto {
    @IsString()
    token: string;

    @IsString()
    @MinLength(6)
    newPassword: string;
}
