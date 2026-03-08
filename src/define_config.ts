import { GuardConfigProvider } from '@adonisjs/auth/types'
import { AccessTokensUserProviderContract } from '@adonisjs/auth/types/access_tokens'
import { Secret } from '@adonisjs/core/helpers'
import type { HttpContext } from '@adonisjs/core/http'
import { Options } from 'jwks-rsa'
import type { StringValue } from 'ms'
import { JwtGuard } from './jwt.js'
import { JwtCookieOptions, JwtGuardUser, JwtUserProviderContract } from './types.js'

export function jwtGuard<UserProvider extends JwtUserProviderContract<unknown>>(config: {
  provider: UserProvider
  refreshTokenUserProvider?: AccessTokensUserProviderContract<unknown>
  tokenName?: string
  tokenExpiresIn?: number | StringValue
  refreshTokenExpiresIn?: number | StringValue
  useCookies?: boolean
  useCookiesForRefreshToken?: boolean
  refreshTokenAbilities?: string[]
  secret: string | Secret<string>
  content: <T>(user: JwtGuardUser<T>) => Record<string | number, any>
  jwks?: Options
  cookie?: JwtCookieOptions
}): GuardConfigProvider<(ctx: HttpContext) => JwtGuard<UserProvider>> {
  return {
    async resolver(_, _app) {
      const secretValue = config.secret instanceof Secret ? config.secret.release() : config.secret
      const options = {
        secret: secretValue,
        refreshTokenUserProvider: config.refreshTokenUserProvider,
        tokenName: config.tokenName,
        expiresIn: config.tokenExpiresIn,
        refreshTokenExpiresIn: config.refreshTokenExpiresIn,
        useCookies: config.useCookies,
        useCookiesForRefreshToken: config.useCookiesForRefreshToken,
        refreshTokenAbilities: config.refreshTokenAbilities,
        content: config.content,
        jwks: config.jwks,
        cookie: config.cookie,
      }
      return (ctx) => new JwtGuard(ctx, config.provider, options)
    },
  }
}
