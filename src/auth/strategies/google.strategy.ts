import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { Strategy, StrategyOptions } from "passport-google-oauth20";


@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
    constructor(configService: ConfigService) {
        super({
            clientID: configService.get<string>('GOOGLE_CLIENT_ID'),
            clientSecret: configService.get<string>('GOOGLE_CLIENT_SECRET'),
            callbackURL: configService.get<string>('GOOGLE_CALLBACK_URL'),
            scope: ['email', 'profile'],
        } as StrategyOptions);
    }
    async validate(accessToken: string, refreshToken: string, profile: any) {
        const { id, emails, displayName } = profile;
        console.log('Inside Google validate!', profile);
        return {
            googleId: id,
            email: emails[0].value,
            name: displayName,
        };
    }
}