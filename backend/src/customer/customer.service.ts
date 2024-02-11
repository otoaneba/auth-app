import { BadRequestException, ConflictException, ForbiddenException, HttpStatus, Injectable, InternalServerErrorException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';
import { GetCustomerInput } from './dto/customer.input';
import { AuthDto, LoginDto } from './dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types'
import { JwtService } from '@nestjs/jwt';
import { Customer, Role } from '@prisma/client';
import * as nodemailer from 'nodemailer';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable()
export class CustomerService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}
  async findAll(params: GetCustomerInput) {
    const { skip, take, cursor, where } = params;

    return this.prisma.customer.findMany({
      skip,
      take,
      cursor,
      where,
    });
  }

  /**
   * @description - Get the customer by email.
   * @param id 
   * @returns 
   */
  async getCustomerByEmail(email: string): Promise<Customer | null> {
    try {
      const customer = await this.prisma.customer.findUniqueOrThrow( {
        where: { email }
      });
      return customer;
    } catch (error) {
      if (error?.code) { // use predefined error code from prisma client
        this.transformPrismaException(error);
      } else {
        throw new InternalServerErrorException('Internal server error occurred while retrieving customer', error)
      }
    }
  }

  /**
   * @description - Sign up with email and password.
   * @param dto 
   * @returns 
   */
  async signupWithEmail(dto: AuthDto): Promise<any> {
    try {
      const hash = await this.hashData(dto.password);
      const newCustomer = await this.prisma.customer.create({
        data: {
          email: dto.email,
          password: hash,
          role: dto.role
        },
      });
      const email = dto.email;
      const verificationToken = this.jwtService.sign({ email }, { expiresIn: '24h' });
      this.sendVerificationEmail(email, verificationToken);
      return { message: 'User registered, please check your email to verify your account' };
    } catch (error) {
      if (error?.code) {
        this.transformPrismaException(error);
      } else {
        throw new InternalServerErrorException("Internal server error");
      }
    }

  }


  /**
   * @description - 
   * @param id 
   * @param updateData 
   * @returns 
   */
  async updateCustomerByEmail(email: string, updateData: Partial<Customer>): Promise<Customer | null> {
    try {
      const customer = await this.prisma.customer.update({
        where: { email },
        data: updateData
      });
      return customer;
    } catch(error) {
      if (error.code) {
        this.transformPrismaException(error)
      } else 
      throw new InternalServerErrorException('Internal server error occurred while retrieving customer', error)
    }
  }
  
  /**
   * 
   * @param email 
   * @param token 
   */
  async sendVerificationEmail(email: string, token: string): Promise<void> {
    const transporter = nodemailer.createTransport({
      host: process.env.MAIL_HOST,
      port: 465,
      secure: false,
      auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASSWORD,
      },
    });
    const mailOptions = {
      from: `AuthApp ${process.env.GMAILADDRESS}`,
      to: email,
      subject: 'Email Verification For Auth App',
      html: `<p>Click <a href="http://localhost:8080/customers/verify?token=${token}">here</a> to verify your email.</p>`,
    };
    await transporter.sendMail(mailOptions);
  }

  /**
   * 
   * @param token 
   */
  async verifyEmail(token: string): Promise<any> {
    try {
      const decoded = this.jwtService.verify(token, { secret: 'at-secret'})
      const customer = await this.getCustomerByEmail(decoded.email);
      if (!customer) throw new Error('Customer not found')
      const update = {confirmed: true}
      const updatedCustomer = this.updateCustomerByEmail(decoded.email, update)
      return updatedCustomer;
    } catch (error) {
      throw new InternalServerErrorException("Internal server error");
    }

  }

  /**
   * 
   * @param loginDto 
   */
  async login(loginDto: LoginDto): Promise<Tokens> {
      const customer = await this.prisma.customer.findUnique({
        where: {
          email: loginDto.email
        }
      });
      if (!customer) throw new NotFoundException("Customer Not Found") 
      if (!customer.confirmed) throw new UnauthorizedException("Please confirm your email to login.");
      
      const passwordMatch = await bcrypt.compare(loginDto.password, customer.password);
      if (!passwordMatch) throw new ForbiddenException("Access Denied");
      
      const tokens = await this.getTokens(customer.id, customer.email, customer.role);
      await this.updateRtHash(customer.id, tokens.refresh_token);
      return tokens;
  }

  /**
   * 
   * @param customerId 
   */
  async logout(customerId: string) {
    await this.prisma.customer.updateMany({
      where: {
        // get customer by id only if hashedRt is not null
        id: customerId,
        hashedRt: {
          not: null,
        }
      },
      // then set the hashedRt to null
      data: {
        hashedRt: null
      }
    })
  }

  /**
   * 
   * @param userId 
   * @param email 
   * @returns 
   */
  async getTokens(userId: string, email: string, role: Role): Promise<Tokens> {
    /**
     * Include the role in the jwt payload so that it's available in the token for access control checks.
     */
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
          role,
        },
        {
          secret: 'at-secret', // Match with AT strategy key. Should be more complex, but hard coded for simplicity for now.
          expiresIn: 60 * 15 // 15 minutes
        }
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
          role,
        },
        {
          secret: 'rt-secret', // Match with RT strategy.
          expiresIn: 60 * 60 * 24 * 7 // One week
        }
      )
    ]);
    return {
      access_token: at,
      refresh_token: rt
    }
  }

  /**
   * 
   * @param data 
   * @returns 
   */
  private hashData(data: string) {
    return bcrypt.hash(data, 10);
  }

  /**
   * @description - Saves the hashed refresh token into the database when the user signs up or logs in.
   * @param customerId 
   * @param rt 
   */
  async updateRtHash(customerId: string, rt: string) {
    const hash = await this.hashData(rt);
    await this.prisma.customer.update({
      where: {
        id: customerId
      },
      data: {
        hashedRt: hash
      }
    })
  }

  async refreshTokens(id: string, refreshToken: string) {
    const customer = await this.prisma.customer.findUnique({
      where: {
        id: id
      }
    });
    if (!customer) throw new ForbiddenException("Access Denied");

    const passwordMatch = await bcrypt.compare(refreshToken, customer.hashedRt);
    if (!passwordMatch) throw new ForbiddenException("Access Denied");

    const tokens = await this.getTokens(customer.id, customer.email, customer.role);
    await this.updateRtHash(customer.id, tokens.refresh_token);
    return tokens;
  }

  /**
   * @description - Deletes user via email.
   * @param id 
   * @returns 
   */
  async deleteUser(email: string): Promise<Customer | null> {
      const result = await this.prisma.customer.delete({
        where: {
          email: email
        }
      });
      return result
  }

  /**
   * 
   * @param error 
   */
  transformPrismaException(error: PrismaClientKnownRequestError) {
    switch (error?.code) {
      case 'P1000': 
        console.log('role base authentication here')
        throw new ForbiddenException("Forbidden.")
      case 'P2002': 
        throw new ConflictException("User with email or ID already exists.")
      case 'P6002': 
      throw new UnauthorizedException("Unauthorized")
      case 'P6005': 
        throw new BadRequestException("Bad request.")
      case 'P2025': 
        throw new NotFoundException("Customer not found.")
      default:
        console.log('filtering default', error.code )
        throw new Error("Error")
    }
  }
}
