import { ArgumentsHost, Catch, ExceptionFilter, HttpStatus } from '@nestjs/common';
import { BaseExceptionFilter } from '@nestjs/core';
import { Prisma } from '@prisma/client';
import { Response } from 'express';


@Catch(Prisma.PrismaClientKnownRequestError)
export class PrismaClientExceptionFilter extends BaseExceptionFilter {
  catch(exception: Prisma.PrismaClientKnownRequestError, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const message = exception.message.replace(/\n/g, '');
    let status = HttpStatus.INTERNAL_SERVER_ERROR;

    switch (exception.code) {
      case 'P1000': 
        console.log('role base authentication here')
        status = HttpStatus.FORBIDDEN;
        response.status(status).json({
          statusCode: status,
          message: message,
        });
        break;
      case 'P2002': 
        status = HttpStatus.CONFLICT;
        response.status(status).json({
          statusCode: status,
          message: `User with email or ID already exists. ${message}`,
        });
        break;
      case 'P6002': 
        status = HttpStatus.UNAUTHORIZED;
        response.status(status).json({
          statusCode: status,
          message: message,
        });
        break;  
      case 'P6005': 
        status = HttpStatus.BAD_REQUEST;
        response.status(status).json({
          statusCode: status,
          message: message,
        });
        break;
      case 'P2002': 
        status = HttpStatus.CONFLICT;
        response.status(status).json({
          statusCode: status,
          message: message,
        });
        break;
      case 'P2025': 
        status = HttpStatus.NOT_FOUND;
        response.status(status).json({
          statusCode: status,
          message: message,
        });
        break;
      
      default:
        console.log('filtering default', exception.code )
        response.status(status).json({
          statusCode: status,
          message: message,
        });
        break;
    }
  }
}
