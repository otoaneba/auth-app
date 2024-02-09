import { Controller, Get, Post, Param, NotFoundException, InternalServerErrorException, Body, Put, UseGuards, Delete, Req, HttpCode, HttpStatus, Query, Res } from '@nestjs/common';
import { CustomerService } from './customer.service';
import { Role } from '@prisma/client';
import { Tokens } from './types'
import { AuthDto, LoginDto } from './dto';
import { AccessTokenGuard, RefreshTokenGuard } from './guards';
import { RequestWithUser } from './types';
import { RolesGuard, Roles } from './roles';
import { GetCurrentCustomer } from './decorators';
import { Response } from 'express';

@Controller('customers')
export class CustomerController {
  constructor(private readonly customerService: CustomerService) {}

  @UseGuards(AccessTokenGuard, RolesGuard) // Match with AT strategy
  @Roles(Role.ADMIN)
  @Put('/update/:email')
  async updateCustomerByEmail(@Param('email') email: string, @Body() updateData: {}) {
    console.log('updating')
    try {
      const result = await this.customerService.updateCustomerByEmail(email, updateData);
      return result;
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw new NotFoundException(error.message)
      } else {
        throw new InternalServerErrorException('Internal server execption');
      }
    }
  }

  @UseGuards(AccessTokenGuard, RolesGuard) // Match with AT strategy
  @Roles(Role.ADMIN)
  @Delete('/delete/:id')
  async deleteUser(@Req() req: RequestWithUser) {
    console.log('deleting from controller', req.user)
    const deletedCustomer = await this.customerService.deleteUser(req.user.sub);
    if (!deletedCustomer) {
      throw new NotFoundException(`User with ID not found`);
    }
    return deletedCustomer;
  }

  @Post('/signupEmail')
  @HttpCode(HttpStatus.CREATED)
  async signupWithEmail(@Body() dto: AuthDto): Promise<Tokens> {
    console.log('signing up')
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
  async login(@Body() dto: LoginDto, @Res() res: Response){
    console.log('logging in controller')
    const tokens = await this.customerService.login(dto);
    console.log('tokens in controller tokens')
    res.json(tokens)
    const temp = this.customerService.login(dto);
    
  }

  @UseGuards(AccessTokenGuard) // Match with AT strategy
  @Post('/logout')
  @HttpCode(HttpStatus.OK)
  logout(@GetCurrentCustomer('sub') id: string) {
    return this.customerService.logout(id)
  }

  // @UseGuards(AccessTokenGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @Post('/logout2')
  @HttpCode(HttpStatus.OK)
  logoutTemp(@Req() req: Request) {
    console.log('request: ', req)
    return this.customerService.logout('asdf')
  }

  @UseGuards(RefreshTokenGuard) // Match with RT strategy
  @Post('/refresh')
  @HttpCode(HttpStatus.OK)
  refreshTokens(@GetCurrentCustomer('sub') id: string, @GetCurrentCustomer('refreshToken') refreshToken: string) {
    return this.customerService.refreshTokens(id, refreshToken)
  }
}
