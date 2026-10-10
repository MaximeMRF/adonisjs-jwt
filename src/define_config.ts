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
  JwtVerifyPayload,
} from './types.js'
import { JwtGuard } from './guard.js'
import type { Secret } from '@adonisjs/core/helpers'
import type { ApplicationService } from '@adonisjs/core/types'
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
  verifyPayload?: JwtVerifyPayload
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
        (usesAsymmetric || config.jwks ? undefined : deriveSecretFromAppKey(readAppKey(app), name))

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
        verifyPayload: config.verifyPayload,
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
function deriveSecretFromAppKey(rawAppKey: string | undefined, guardName: string) {
  if (!rawAppKey || rawAppKey.length < 32) {
    throw new Error(
      'JWT guard requires the application key (APP_KEY) to be at least 32 characters when no `secret` is configured'
    )
  }

  return Buffer.from(
    hkdfSync('sha256', rawAppKey, '', `@maximemrf/adonisjs-jwt:${guardName}`, 32)
  ).toString('hex')
}

/**
 * AdonisJS v6 exposes the app key as `app.appKey` in config/app.ts. AdonisJS
 * v7 apps only pass APP_KEY to config/encryption.ts, and the env loader
 * copies it to process.env.
 */
function readAppKey(app: ApplicationService): string | undefined {
  const appKey = app.config.get<Secret<string> | string | undefined>('app.appKey', undefined)
  if (appKey) {
    return typeof appKey === 'string' ? appKey : appKey.release()
  }

  return process.env.APP_KEY
}
