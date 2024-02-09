import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from 'passport-jwt';

type JwtPayload = {
  sub: string;
  email: string;
}

@Injectable()
export class AccessTokenStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: 'at-secret' // update and save these into config
    });
  }

  // payload is the decoded token. When the token is received by passport, it will be decoded into the token and that object will then passed into this payload
  validate(payload: any) {
    // under the hood, express is doing req.user = payload
    console.log('validating from at strategy', payload)
    return payload;
  }
}