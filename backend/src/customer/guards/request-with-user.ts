import { Role } from '@prisma/client';
import { Request } from 'express';

export interface RequestWithUser extends Request {
  user: {
    sub: string;
    email: string;
    role: Role;
    iat: number;
    exp: number;
  }
}
