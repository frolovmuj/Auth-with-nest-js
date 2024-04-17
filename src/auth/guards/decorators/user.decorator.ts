import { ExecutionContext, createParamDecorator } from '@nestjs/common';

import { User } from '@prisma/client';

export const currentUser = createParamDecorator(
  (data: keyof User, ctx: ExecutionContext) => {
    const req = ctx.switchToHttp().getRequest();
    const user = req.user;

    return data ? user(data) : user
  },
);
