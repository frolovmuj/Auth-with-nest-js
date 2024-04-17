import { JwtAuthGuard } from '../jwt.guard';
import { UseGuards } from '@nestjs/common';

export const Auth = () => UseGuards(JwtAuthGuard);
