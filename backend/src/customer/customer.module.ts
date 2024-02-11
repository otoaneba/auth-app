import { Module } from '@nestjs/common';
import { CustomerService } from './customer.service';
import { PrismaService } from 'src/prisma.service';
import { CustomerResolver } from './customer.resolver';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { RefreshTokenStrategy, AccessTokenStrategy } from './strategies'
import { CustomerController } from './customer.controller';

@Module({
  imports: [PassportModule,
    JwtModule.register({
      secret: process.env.AT_KEY, // Ensure this is securely managed
      signOptions: { expiresIn: '15m' }, }),
  ],
  controllers: [CustomerController],
  providers: [CustomerService, PrismaService, AccessTokenStrategy, RefreshTokenStrategy,CustomerResolver],
})
export class CustomerModule {}
