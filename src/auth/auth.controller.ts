import { Body, Controller, Get, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SigninDto, SignupDto } from './dtos/auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signup(@Body() user: SignupDto) {
    return this.authService.signup(user);
  }

  @Post('signin')
  signin(@Body() user: SigninDto) {
    return this.authService.signin(user);
  }
}
