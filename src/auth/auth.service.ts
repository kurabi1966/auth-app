import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { DatabaseService } from 'src/database/database.service';
import { SigninDto, SignupDto } from './dtos/auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private readonly config: ConfigService,
    private readonly db: DatabaseService,
    private readonly jwt: JwtService,
  ) {}

  async signup(new_user: SignupDto) {
    const { email, password } = new_user;
    // TODO
    // 1. find a user with the same email
    // 2. if exist: throw an error
    // 3. if not: create a user and save to the database
    // 4. Do not forget encrypting the passaword

    const existing_user = await this.db.user.findUnique({ where: { email } });
    if (existing_user) {
      throw new BadRequestException(`Email ${email} already used`);
    }
    const hashedPassword = await this.hashPassword(password);
    const user = await this.db.user.create({ data: { email, hashedPassword } });
    return { id: user.id, email: user.email };
  }

  async signin(user: SigninDto) {
    const { email, password } = user;
    // TODO
    // 1. Find the user
    // 2 If not exist, throw an error
    // 3. if exist, compare his password to his hashed password

    const userExist = await this.db.user.findUnique({ where: { email } });

    if (!userExist) {
      throw new UnauthorizedException('Incorrect credentials');
    }

    const isMatch = await this.isMatch(password, userExist.hashedPassword);

    if (!isMatch) {
      throw new UnauthorizedException('Incorrect credentials');
    }

    // TODO
    // Create access token and refresh token and send back to the user
    const access_token = await this.jwt.signAsync(
      {
        id: userExist.id,
        email: userExist.email,
      },
      {
        secret: this.config.get<string>('JWT_ACCESS_SECRET'),
        expiresIn: '15m',
      },
    );
    const refresh_token = await this.jwt.signAsync(
      {
        id: userExist.id,
        email: userExist.email,
      },
      {
        secret: this.config.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: '7d',
      },
    );
    return { access_token, refresh_token };
  }

  private async hashPassword(password: string) {
    return await bcrypt.hash(password, 10);
  }
  private async isMatch(password: string, hashedPassword: string) {
    return await bcrypt.compare(password, hashedPassword);
  }
}
