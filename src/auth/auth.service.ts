import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signin(dto: AuthDto) {
    // find the user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    // if user does not exists throw exception
    if (!user) throw new ForbiddenException('Credentials incorrect');

    // compare password
    const pwMatches = await argon.verify(user.hash, dto.password);

    // if password incorrect throw exception
    if (!pwMatches) throw new ForbiddenException('Credentials incorrect');

    // send back the user
    delete user.hash;
    return this.signToken(user.id, user.email);
  }

  async signup(dto: AuthDto) {
    // find the user by email
    const oldUser = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    // if user exists throw exception because email is unique field
    if (oldUser) throw new ForbiddenException('Credentials Taken');

    // generate password
    const hash = await argon.hash(dto.password);
    // save the new ser in the db
    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        hash,
      },
    });

    // remove hash password and return the saved user
    delete user.hash;
    return this.signToken(user.id, user.email);
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };
    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m', // 15 minutes
      secret: this.config.get('JWT_SECRET'),
    });
    return {
      access_token: token,
    };
  }
}
