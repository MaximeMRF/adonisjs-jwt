import jwt from 'jsonwebtoken'
import { errors } from '@adonisjs/auth'
import type { Options } from 'jwks-rsa'
import type { StringValue } from 'ms'
import { JwksManager } from '../jwks.js'
import type { JwtDriver } from './types.js'
import { ALLOWED_JWKS_ALGORITHMS } from '../types.js'

export class JwksDriver implements JwtDriver {
  readonly canSign = false
  #jwksManager: JwksManager
  #issuer?: string
  #audience?: string | string[]

  constructor(options: Options, driverOptions?: { issuer?: string; audience?: string | string[] }) {
    this.#jwksManager = new JwksManager(options)
    this.#issuer = driverOptions?.issuer
    this.#audience = driverOptions?.audience
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
      algorithms: [...ALLOWED_JWKS_ALGORITHMS],
      ...(this.#issuer ? { issuer: this.#issuer } : {}),
      ...(this.#audience ? { audience: this.#audience } : {}),
    }
    return jwt.verify(token, key, verifyOptions)
  }
}
