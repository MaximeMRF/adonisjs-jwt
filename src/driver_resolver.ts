import type { Options } from 'jwks-rsa'
import type { JwtAsymmetricAlgorithm, JwtJwksAlgorithm } from './types.js'
import type { JwtDriver } from './drivers/types.js'
import { SymmetricDriver } from './drivers/symmetric.js'
import { AsymmetricDriver } from './drivers/asymmetric.js'
import { JwksDriver } from './drivers/jwks.js'

export function resolveDriver(
  options: {
    driver?: JwtDriver
    secret?: string
    privateKey?: string
    publicKey?: string
    algorithm?: JwtAsymmetricAlgorithm
    jwks?: Options
    issuer?: string
    audience?: string | string[]
    algorithms?: JwtJwksAlgorithm[]
  },
  contextName = 'JWT guard'
): JwtDriver {
  if (options.driver) {
    return options.driver
  }

  const usesAsymmetric =
    options.privateKey !== undefined &&
    options.publicKey !== undefined &&
    options.algorithm !== undefined

  if (options.jwks) {
    try {
      return new JwksDriver(options.jwks, {
        issuer: options.issuer,
        audience: options.audience,
        algorithms: options.algorithms,
      })
    } catch (error) {
      throw new Error(`${contextName} JWKS validation failed: ${(error as Error).message}`)
    }
  }

  if (usesAsymmetric) {
    try {
      return new AsymmetricDriver({
        privateKey: options.privateKey!,
        publicKey: options.publicKey!,
        algorithm: options.algorithm!,
        issuer: options.issuer,
        audience: options.audience,
      })
    } catch (error) {
      throw new Error(
        `${contextName} asymmetric key validation failed: ${(error as Error).message}`
      )
    }
  }

  return new SymmetricDriver({
    secret: options.secret!,
    issuer: options.issuer,
    audience: options.audience,
  })
}
