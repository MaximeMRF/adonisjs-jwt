import type { GuardConfigProvider } from '@adonisjs/auth/types'
import type { HttpContext } from '@adonisjs/core/http'
import type {
  JwtAsymmetricAlgorithm,
  JwtGuardUser,
  JwtUserProviderContract,
  JwtCookieOptions,
} from './types.js'
import { JwtGuard } from './jwt.js'
import type { Secret } from '@adonisjs/core/helpers'
import type { StringValue } from 'ms'
import type { AccessTokensUserProviderContract } from '@adonisjs/auth/types/access_tokens'
import type { Options } from 'jwks-rsa'
import { createPrivateKey, createPublicKey } from 'node:crypto'

function validateAsymmetricConfig(config: {
  privateKey?: string
  publicKey?: string
  algorithm?: JwtAsymmetricAlgorithm
  jwks?: Options
}) {
  const partial =
    config.privateKey !== undefined ||
    config.publicKey !== undefined ||
    config.algorithm !== undefined

  if (!partial) {
    return
  }

  if (!config.privateKey || !config.publicKey || !config.algorithm) {
    throw new Error(
      'JWT guard asymmetric mode requires `privateKey`, `publicKey`, and `algorithm` to be set together'
    )
  }

  if (config.jwks) {
    throw new Error(
      'JWT guard cannot use `jwks` together with asymmetric `privateKey` / `publicKey`'
    )
  }

  const expectedKeyType = config.algorithm.startsWith('RS')
    ? 'rsa'
    : config.algorithm.startsWith('ES')
      ? 'ec'
      : null

  if (!expectedKeyType) {
    throw new Error(`Unsupported asymmetric algorithm "${config.algorithm}"`)
  }

  try {
    const privateKey = createPrivateKey(config.privateKey)
    const publicKey = createPublicKey(config.publicKey)

    if (privateKey.asymmetricKeyType !== expectedKeyType) {
      throw new Error(
        `privateKey type "${privateKey.asymmetricKeyType}" does not match algorithm "${config.algorithm}"`
      )
    }
    if (publicKey.asymmetricKeyType !== expectedKeyType) {
      throw new Error(
        `publicKey type "${publicKey.asymmetricKeyType}" does not match algorithm "${config.algorithm}"`
      )
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Invalid asymmetric key configuration'
    throw new Error(`JWT guard asymmetric key validation failed: ${message}`)
  }
}

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
  privateKey?: string
  publicKey?: string
  algorithm?: JwtAsymmetricAlgorithm
  content: <T>(user: JwtGuardUser<T>) => Record<string | number, any>
  jwks?: Options
  cookie?: JwtCookieOptions
}): GuardConfigProvider<(ctx: HttpContext) => JwtGuard<UserProvider>> {
  return {
    async resolver(_, app) {
      validateAsymmetricConfig(config)

      const appKey = (app.config.get('app.appKey') as Secret<string>).release()
      const usesAsymmetric =
        config.privateKey !== undefined &&
        config.publicKey !== undefined &&
        config.algorithm !== undefined

      const options = {
        ...(usesAsymmetric
          ? {
              privateKey: config.privateKey,
              publicKey: config.publicKey,
              algorithm: config.algorithm,
            }
          : {
              secret: config.secret ?? appKey,
            }),
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
