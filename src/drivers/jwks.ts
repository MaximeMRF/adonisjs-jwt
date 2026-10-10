import jwt from 'jsonwebtoken'
import { errors } from '@adonisjs/auth'
import type { Options } from 'jwks-rsa'
import type { StringValue } from 'ms'
import { JwksManager } from '../jwks.js'
import type { JwtDriver } from './types.js'
import { ALLOWED_JWKS_ALGORITHMS, type JwtJwksAlgorithm } from '../types.js'

/**
 * Safe jwks-rsa defaults: tokens with an unknown `kid` trigger a JWKS
 * fetch, so fetches must be cached and rate limited to avoid hammering
 * the identity provider. They can be overridden through the `jwks` option.
 */
export const DEFAULT_JWKS_OPTIONS = {
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 10,
  timeout: 5000,
} satisfies Partial<Options>

export class JwksDriver implements JwtDriver {
  readonly canSign = false
  #jwksManager: JwksManager
  #issuer?: string
  #audience?: string | string[]
  #clockTolerance?: number
  #algorithms: JwtJwksAlgorithm[]

  constructor(
    options: Options,
    driverOptions?: {
      issuer?: string
      audience?: string | string[]
      algorithms?: JwtJwksAlgorithm[]
      clockTolerance?: number
      verifiesPayload?: boolean
    }
  ) {
    if (
      !driverOptions?.issuer ||
      !(hasAudience(driverOptions.audience) || driverOptions.verifiesPayload)
    ) {
      throw new Error(
        '`issuer` and either `audience` or `verifyPayload` are required, otherwise any token signed by the identity provider is accepted, including tokens issued for other applications'
      )
    }

    const algorithms = driverOptions.algorithms ?? [...ALLOWED_JWKS_ALGORITHMS]
    if (algorithms.length === 0) {
      throw new Error('`algorithms` must not be empty')
    }
    const unsupported = algorithms.filter(
      (alg) => !(ALLOWED_JWKS_ALGORITHMS as readonly string[]).includes(alg)
    )
    if (unsupported.length > 0) {
      throw new Error(
        `unsupported algorithm(s): ${unsupported.join(', ')}. Allowed: ${ALLOWED_JWKS_ALGORITHMS.join(', ')}`
      )
    }

    this.#jwksManager = new JwksManager({ ...DEFAULT_JWKS_OPTIONS, ...options })
    this.#issuer = driverOptions.issuer
    this.#audience = driverOptions.audience
    this.#clockTolerance = driverOptions.clockTolerance
    this.#algorithms = algorithms
  }

  sign(_payload: Record<string, any>, _options?: { expiresIn?: number | StringValue }): never {
    throw new errors.E_UNAUTHORIZED_ACCESS("You can't use the auth.generate method with jwks", {
      guardDriverName: 'jwt',
    })
  }

  async verify(token: string): Promise<Record<string, any> | string> {
    const decoded = jwt.decode(token, { complete: true })
    if (!decoded || !decoded.header || !decoded.header.kid || !decoded.header.alg) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: 'jwt',
      })
    }
    const key = await this.#jwksManager.getSigningKey(decoded.header.kid)
    const verifyOptions: jwt.VerifyOptions = {
      algorithms: [...this.#algorithms],
      ...(this.#issuer ? { issuer: this.#issuer } : {}),
      ...(this.#audience ? { audience: this.#audience as jwt.VerifyOptions['audience'] } : {}),
      ...(this.#clockTolerance !== undefined ? { clockTolerance: this.#clockTolerance } : {}),
    }
    return jwt.verify(token, key, verifyOptions)
  }
}

function hasAudience(audience?: string | string[]) {
  return Array.isArray(audience)
    ? audience.length > 0 && audience.every(Boolean)
    : Boolean(audience)
}
