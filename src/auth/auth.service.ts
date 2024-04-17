import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';

import { AuthDto } from './dto/auth.dto';
import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';
import { UserService } from 'src/user/user.service';
import { verify } from 'argon2';

@Injectable()
export class AuthService {
  constructor(
    private jwt: JwtService,
    private userService: UserService,
  ) {}

  EXPIRE_DAY_REFRESH_TOKEN = 1;
  REFRESH_TOKEN_NAME = 'refreshToken';

  async login(dto: AuthDto) {
    const { password, ...user } = await this.validateUser(dto);
    const tokens = this.issueTokens(user.id);

    return {
      user,
      ...tokens,
    };
  }

  async register(dto: AuthDto) {
    const oldUser = await this.userService.getByEmail(dto.email);

    if (oldUser) throw new BadRequestException('user already exists');

    const { password, ...user } = await this.userService.create(dto);
    const tokens = this.issueTokens(user.id);

    return {
      user,
      ...tokens,
    };
  }
  async getNewTokens(refreshToken: string) {
    const res = await this.jwt.verifyAsync(refreshToken);
    if (!res) throw new UnauthorizedException('indalid refresh token');

    const { password, ...user } = await this.userService.getById(res.id);

    const newTokens = this.issueTokens(res.id);

    return {
      ...newTokens,
      user,
    };
  }

  private issueTokens(userId: string) {
    const data = { id: userId };

    const accessToken = this.jwt.sign(data, {
      expiresIn: '1h',
    });
    const refreshToken = this.jwt.sign(data, {
      expiresIn: '7d',
    });

    return { accessToken, refreshToken };
  }

  private async validateUser(dto: AuthDto) {
    const user = await this.userService.getByEmail(dto.email);

    if (!user) throw new NotFoundException('user not found');

    const isValid = await verify(user.password, dto.password);

    if (!isValid) throw new NotFoundException('password not valid');

    return user;
  }

  addRefreshTokenToResponse(res: Response, refreshToken: string) {
    const expiresIn = new Date();
    expiresIn.setDate(expiresIn.getDate() + this.EXPIRE_DAY_REFRESH_TOKEN);

    res.cookie(this.REFRESH_TOKEN_NAME, refreshToken, {
      httpOnly: true,
      domain: 'localhost',
      expires: expiresIn,
      secure: true,
      sameSite: 'none',
    });
  }
  removeRefreshTokenFromResponse(res: Response) {
    res.cookie(this.REFRESH_TOKEN_NAME, '', {
      httpOnly: true,
      domain: 'localhost',
      expires: new Date(0),
      secure: true,
      sameSite: 'none',
    });
  }
}
