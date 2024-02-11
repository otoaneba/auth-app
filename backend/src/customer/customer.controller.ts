import { Controller, Get, Post, Param, NotFoundException, InternalServerErrorException, Body, Put, UseGuards, Delete, Req, HttpCode, HttpStatus, Query, Res, UseFilters } from '@nestjs/common';
import { CustomerService } from './customer.service';
import { Role } from '@prisma/client';
import { Tokens } from './types'
import { AuthDto, LoginDto } from './dto';
import { AccessTokenGuard, RefreshTokenGuard } from './guards';
import { RolesGuard, Roles } from './roles';
import { GetCurrentCustomer } from './decorators';
import { Response } from 'express';

@Controller('customers')
export class CustomerController {
  constructor(private readonly customerService: CustomerService) {}

  @Get('/lookup/:email')
  @UseGuards(AccessTokenGuard)
  async getCustomerByEmail(@Param('email') email: string) {
    return await this.customerService.getCustomerByEmail(email);
  }

  @UseGuards(AccessTokenGuard, RolesGuard) // Match with AT strategy
  @Roles(Role.ADMIN)
  @Put('/update/:email')
  async updateCustomerByEmail(@Param('email') email: string, @Body() updateData: {}) {
    console.log('updating')
      const result = await this.customerService.updateCustomerByEmail(email, updateData);
      return result;
  }

  @UseGuards(AccessTokenGuard, RolesGuard) // Match with AT strategy
  @Roles(Role.ADMIN)
  @Delete('/delete/:email')
  async deleteUser(@Param('email') email: string) {
    const deletedCustomer = await this.customerService.deleteUser(email);
    if (!deletedCustomer) {
      throw new NotFoundException(`User with ID not found`);
    }
    return deletedCustomer;
  }

  @Post('/signupEmail')
  @HttpCode(HttpStatus.CREATED)
  async signupWithEmail(@Body() dto: AuthDto): Promise<Tokens> {
    return this.customerService.signupWithEmail(dto);
  }

  @Get('/verify')
  async verifyEmail(@Query('token') token: string, @Res() res: Response): Promise<any> {
    // Verify the token using JwtService, decode it, and update the user's verification status in the database
    // Redirect the user to a confirmation page or show a verification success message
    this.customerService.verifyEmail(token);
    res.redirect('http://localhost:3000/react/email-verified');
  }

  @Post('/login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() dto: LoginDto, @Res() res: Response) {
    try {
      const tokens = await this.customerService.login(dto);
      // return tokens in httponly cookie ie
      /**
       *  res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: true, // for https
            sameSite: 'strict', 
            path: '/',
            maxAge: 24 * 60 * 60 * 1000,
          });
       */
      res.json(tokens)
    } catch (error) {
      res.status(error.status || 500).json({
        message: error.response || 'Internal server error',
      });
    }
  }

  @UseGuards(RefreshTokenGuard) // Match with RT strategy
  @Post('/refresh')
  @HttpCode(HttpStatus.OK)
  refreshTokens(@GetCurrentCustomer('sub') id: string, @GetCurrentCustomer('refreshToken') refreshToken: string) {
    return this.customerService.refreshTokens(id, refreshToken)
  }
}
