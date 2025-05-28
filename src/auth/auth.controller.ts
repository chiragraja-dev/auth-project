import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto, SignupDto } from './dto/auth.dto';

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
}
