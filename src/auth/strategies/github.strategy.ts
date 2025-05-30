import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { Strategy, StrategyOptions } from "passport-github2";

@Injectable()
export class GithubStartegy extends PassportStrategy(Strategy, 'github') {
    constructor(configService: ConfigService) {
        super({
            clientID: configService.get<string>('GITHUB_CLIENT_ID'),
            clientSecret: configService.get<string>('GITHUB_CLIENT_SECRET'),
            callbackURL: configService.get<string>('GITHUB_CALLBACK_URL'),
            scope: ['user:email']
        } as StrategyOptions)
    }

    validate(accessToken: string, refreshToken: string, profile: any) {
        const { id, emails, displayName, userName } = profile;
        return {
            githubId: id,
            email: emails && emails.length > 0 ? emails[0].value : null,
            name: displayName ?? userName
        }
    }

}