import type { GuardConfigProvider } from '@adonisjs/auth/types'
import type { HttpContext } from '@adonisjs/core/http'
import type {
  JwtAsymmetricAlgorithm,
  JwtGuardUser,
  JwtUserProviderContract,
  JwtCookieOptions,
  BaseJwtContent,
  JwtJwksAlgorithm,
  JwtGetUserId,
} from './types.js'
import { JwtGuard } from './guard.js'
import type { Secret } from '@adonisjs/core/helpers'
import type { StringValue } from 'ms'
import type { AccessTokensUserProviderContract } from '@adonisjs/auth/types/access_tokens'
import type { Options } from 'jwks-rsa'
import { validateGuardOptions } from './validation.js'
import { resolveDriver } from './driver_resolver.js'

export function jwtGuard<UserProvider extends JwtUserProviderContract<unknown>>(config: {
  provider: UserProvider
  refreshTokenUserProvider?: AccessTokensUserProviderContract<unknown>
  tokenName?: string
  refreshTokenName?: string
  tokenExpiresIn?: number | StringValue
  refreshTokenExpiresIn?: number | StringValue
  useCookies?: boolean
  useCookiesForRefreshToken?: boolean
  refreshTokenAbilities?: string[]
  secret?: string
  privateKey?: string
  publicKey?: string
  algorithm?: JwtAsymmetricAlgorithm
  content?: <T>(user: JwtGuardUser<T>) => Record<string, any> & BaseJwtContent
  jwks?: Options
  cookie?: JwtCookieOptions
  issuer?: string
  audience?: string | string[]
  algorithms?: JwtJwksAlgorithm[]
  clockTolerance?: number
  getUserId?: JwtGetUserId
}): GuardConfigProvider<(ctx: HttpContext) => JwtGuard<UserProvider>> {
  return {
    async resolver(_, app) {
      const appKey = (app.config.get('app.appKey') as Secret<string>).release()
      const resolvedSecret = config.secret ?? appKey

      const resolvedConfig = {
        ...config,
        secret: resolvedSecret,
      }

      validateGuardOptions(resolvedConfig, 'JWT guard')

      const driver = resolveDriver(resolvedConfig, 'JWT guard')

      const usesAsymmetric =
        config.privateKey !== undefined &&
        config.publicKey !== undefined &&
        config.algorithm !== undefined

      const options = {
        driver,
        ...(usesAsymmetric
          ? {
              privateKey: config.privateKey,
              publicKey: config.publicKey,
              algorithm: config.algorithm,
            }
          : {
              secret: resolvedSecret,
            }),
        refreshTokenUserProvider: config.refreshTokenUserProvider,
        tokenName: config.tokenName,
        refreshTokenName: config.refreshTokenName,
        expiresIn: config.tokenExpiresIn,
        refreshTokenExpiresIn: config.refreshTokenExpiresIn,
        useCookies: config.useCookies,
        useCookiesForRefreshToken: config.useCookiesForRefreshToken,
        refreshTokenAbilities: config.refreshTokenAbilities,
        content: config.content,
        jwks: config.jwks,
        cookie: config.cookie,
        issuer: config.issuer,
        audience: config.audience,
        algorithms: config.algorithms,
        clockTolerance: config.clockTolerance,
        getUserId: config.getUserId,
      }
      return (ctx) => new JwtGuard(ctx, config.provider, options)
    },
  }
}
