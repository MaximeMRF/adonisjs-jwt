import { GuardConfigProvider } from '@adonisjs/auth/types'
import type { HttpContext } from '@adonisjs/core/http'
import { JwtGuardUser, JwtUserProviderContract } from './types.js'
import { JwtGuard } from './jwt.js'
import { Secret } from '@adonisjs/core/helpers'
import type { StringValue } from 'ms'
import { AccessTokensUserProviderContract } from '@adonisjs/auth/types/access_tokens'

export function jwtGuard<UserProvider extends JwtUserProviderContract<unknown>>(config: {
  provider: UserProvider
  refreshTokenUserProvider?: AccessTokensUserProviderContract<unknown>
  tokenName?: string
  tokenExpiresIn?: number | StringValue
  refreshTokenExpiresIn?: number | StringValue
  useCookies?: boolean
  useCookiesForRefreshToken?: boolean
  refreshTokenAbilities?: string[]
  secret?: string
  content: <T>(user: JwtGuardUser<T>) => Record<string | number, any>
}): GuardConfigProvider<(ctx: HttpContext) => JwtGuard<UserProvider>> {
  return {
    async resolver(_, app) {
      const appKey = (app.config.get('app.appKey') as Secret<string>).release()
      const options = {
        secret: config.secret ?? appKey,
        refreshTokenUserProvider: config.refreshTokenUserProvider,
        tokenName: config.tokenName,
        expiresIn: config.tokenExpiresIn,
        refreshTokenExpiresIn: config.refreshTokenExpiresIn,
        useCookies: config.useCookies,
        useCookiesForRefreshToken: config.useCookiesForRefreshToken,
        refreshTokenAbilities: config.refreshTokenAbilities,
        content: config.content,
      }
      return (ctx) => new JwtGuard(ctx, config.provider, options)
    },
  }
}
