import { Body, Controller, Get, Post, Req, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto, SignupDto } from './dto/auth.dto';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Post('signup')
  async signup(@Body() data: SignupDto): Promise<{ token: string, user: { email: string, name?: string } }> {
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

}
