import { Prisma } from '@prisma/client';
import * as bcrypt from 'bcrypt';

export const customers: Prisma.CustomerUpsertArgs['create'][] = [
  {
    id: '9e391faf-64b2-4d4c-b879-463532920fd3',
    email: 'user@gmail.com',
    password: 'randow-password',
    confirmed: true,
  },
  {
    id: '9e391faf-64b2-4d4c-b879-463532920fd4',
    email: 'user2@gmail.com',
    password: 'randow-password',
    confirmed: true,
  },
  {
    id: '9e391faf-64b2-4d4c-b879-463532920fd5',
    email: 'admin@gmail.com',
    role: 'ADMIN',
    confirmed: true,
    password: "asdfasdf"
  },
];
