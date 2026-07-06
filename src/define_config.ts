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
import { SymmetricDriver } from './drivers/symmetric.js'
import { AsymmetricDriver } from './drivers/asymmetric.js'
import { JwksDriver } from './drivers/jwks.js'
import type { JwtDriver } from './drivers/types.js'

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

  const usesAsymmetric =
    config.privateKey !== undefined &&
    config.publicKey !== undefined &&
    config.algorithm !== undefined

  if (partial && !usesAsymmetric) {
    throw new Error(
      'JWT guard asymmetric mode requires `privateKey`, `publicKey`, and `algorithm` to be set together'
    )
  }

  if (config.jwks && usesAsymmetric) {
    throw new Error(
      'JWT guard cannot use `jwks` together with asymmetric `privateKey` / `publicKey`'
    )
  }

  if (usesAsymmetric) {
    try {
      new AsymmetricDriver({
        privateKey: config.privateKey!,
        publicKey: config.publicKey!,
        algorithm: config.algorithm!,
      })
    } catch (error) {
      const message =
        error instanceof Error ? error.message : 'Invalid asymmetric key configuration'
      const cleanMessage = message.includes('JwtGuard asymmetric key validation failed: ')
        ? message.replace('JwtGuard asymmetric key validation failed: ', '')
        : message
      throw new Error(`JWT guard asymmetric key validation failed: ${cleanMessage}`)
    }
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

      let driver: JwtDriver
      if (config.jwks) {
        driver = new JwksDriver(config.jwks)
      } else if (usesAsymmetric) {
        driver = new AsymmetricDriver({
          privateKey: config.privateKey!,
          publicKey: config.publicKey!,
          algorithm: config.algorithm!,
        })
      } else {
        driver = new SymmetricDriver({
          secret: config.secret ?? appKey,
        })
      }

      const options = {
        driver,
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
