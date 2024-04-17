import { AuthDto } from 'src/auth/dto/auth.dto';
import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';
import { User } from '@prisma/client';
import { hash } from 'argon2';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}
  getById(id: string) {
    return this.prisma.user.findUnique({
      where: {
        id,
      },
      include: {
        tasks: true,
      },
    });
  }
  getByEmail(email: string) {
    return this.prisma.user.findUnique({
      where: {
        email,
      },
    });
  }
  async getAll() {
    const users = await this.prisma.user.findMany({});
    return this.selectUsersWithoutPassword(users);
  }
  async create(dto: AuthDto) {
    const user = {
      email: dto.email,
      name: '',
      password: await hash(dto.password),
    };
    return this.prisma.user.create({
      data: user,
    });
  }
  
  private selectUsersWithoutPassword(users: User[]): Omit<User, 'password'>[] {
    return users.map(({ password, ...user }) => user);
  }
}
