import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
// import { Role } from '@prisma/client';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    try {
      const requiredRoles = this.reflector.get<string[]>('roles', context.getHandler());
      if (!requiredRoles) {
        return true;
      }
      const request = context.switchToHttp().getRequest();
      const user = request.user;
      return requiredRoles.some((role) => user.role?.includes(role));
    } catch (error) {
      console.log('Catch in roles guard.')
    }
    
  }
}