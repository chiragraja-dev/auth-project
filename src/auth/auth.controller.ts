import { Body, Controller, Get, Post, Req, UseGuards, Request, Logger } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto, SignupDto } from './dto/auth.dto';
import { AuthGuard } from '@nestjs/passport';
import { ForgetPasswordDto, ResetPasswordDto } from './dto/reset-password.dto';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);
  constructor(private readonly authService: AuthService) { }

  @Post('signup')
  async signup(@Body() data: SignupDto): Promise<{ message: string, email: string, name: string }> {
    return await this.authService.signup(data)
  }

  @Post('login')
  async login(@Body() data: LoginDto): Promise<{ token: string, user: { email: string, name?: string } }> {
    return await this.authService.login(data)
  }

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() { }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Request() req) {
    return this.authService.loginWithGoogle(req.user)
  }

  @Get('github')
  @UseGuards(AuthGuard('github'))
  async githubAuth() { }

  @Get('github/callback')
  @UseGuards(AuthGuard('github'))
  async githubAuthRedirect(@Request() req) {
    return this.authService.loginWithGithub(req.user)
  }

  @Post('forget-password')
  async forgetPassword(@Body() forgetPasswordDto: ForgetPasswordDto) {
    this.logger.log(`Password reset requested for email: ${forgetPasswordDto.email}`);
    const result = await this.authService.forgetPassword(forgetPasswordDto.email);
    return {
      success: result.success,
      message: result.message,
      timestamp: new Date().toISOString()
    };
  }

  @Post('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto) {
    return this.authService.resetPassword(dto.token, dto.newPassword)
  }

  @Post('verify')
  async verifyOtp(@Body() req: { email: string, otp: string }) {
    return this.authService.verifyOtp(req.email, req.otp)
  }

}
