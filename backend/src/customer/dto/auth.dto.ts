import { IsNotEmpty, IsString } from "class-validator";

export class AuthDto {
  @IsNotEmpty()
  @IsString()
  email: string;
  password: string;
}

export class LoginDto {
  @IsNotEmpty()
  @IsString()
  email: string;
  password: string;
}