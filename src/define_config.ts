import type { symbols } from '@adonisjs/auth'
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
import { hkdfSync } from 'node:crypto'

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
  content?: (
    user: JwtGuardUser<UserProvider[typeof symbols.PROVIDER_REAL_USER]>
  ) => Record<string, any> & BaseJwtContent
  jwks?: Options
  cookie?: JwtCookieOptions
  issuer?: string
  audience?: string | string[]
  algorithms?: JwtJwksAlgorithm[]
  clockTolerance?: number
  getUserId?: JwtGetUserId
}): GuardConfigProvider<(ctx: HttpContext) => JwtGuard<UserProvider>> {
  return {
    async resolver(name, app) {
      const asymmetricKeys = {
        privateKey: config.privateKey,
        publicKey: config.publicKey,
        algorithm: config.algorithm,
      }
      const usesAsymmetric = Object.values(asymmetricKeys).some((value) => value !== undefined)

      /**
       * Only fall back on the app key when no other signing method is configured
       */
      const resolvedSecret =
        config.secret ??
        (usesAsymmetric || config.jwks
          ? undefined
          : deriveSecretFromAppKey(app.config.get('app.appKey'), name))

      const options = {
        ...(usesAsymmetric ? asymmetricKeys : { secret: resolvedSecret }),
        refreshTokenUserProvider: config.refreshTokenUserProvider,
        tokenName: config.tokenName,
        refreshTokenName: config.refreshTokenName,
        tokenExpiresIn: config.tokenExpiresIn,
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

      validateGuardOptions(options, 'JWT guard')

      const driver = resolveDriver(options, 'JWT guard')

      return (ctx) => new JwtGuard(ctx, config.provider, { ...options, driver })
    },
  }
}

/**
 * Derive a dedicated signing key from the app key, so the guard never signs
 * with the raw app key used elsewhere by the application, and two JWT guards
 * never accept each other's tokens.
 */
function deriveSecretFromAppKey(appKey: Secret<string> | undefined, guardName: string) {
  const rawAppKey = appKey?.release()
  if (!rawAppKey || rawAppKey.length < 32) {
    throw new Error(
      'JWT guard requires `app.appKey` to be at least 32 characters when no `secret` is configured'
    )
  }

  return Buffer.from(
    hkdfSync('sha256', rawAppKey, '', `@maximemrf/adonisjs-jwt:${guardName}`, 32)
  ).toString('hex')
}
