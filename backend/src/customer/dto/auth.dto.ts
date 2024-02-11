import { Role } from "@prisma/client";
import { IsNotEmpty, IsString } from "class-validator";

export class AuthDto {
  @IsNotEmpty()
  @IsString()
  email: string;
  password: string;
  role?: Role
}

export class LoginDto {
  @IsNotEmpty()
  @IsString()
  email: string;
  password: string;
}