import jwt from 'jsonwebtoken'
import { errors } from '@adonisjs/auth'
import type { Options } from 'jwks-rsa'
import type { StringValue } from 'ms'
import { JwksManager } from '../jwks.js'
import type { JwtDriver } from './types.js'

export class JwksDriver implements JwtDriver {
  readonly canSign = false
  #jwksManager: JwksManager

  constructor(options: Options) {
    this.#jwksManager = new JwksManager(options)
  }

  sign(_payload: Record<string, any>, _options?: { expiresIn?: number | StringValue }): never {
    throw new errors.E_UNAUTHORIZED_ACCESS("You can't use the auth.generate method with jwks", {
      guardDriverName: 'jwt',
    })
  }

  async verify(token: string): Promise<Record<string, any> | string> {
    const decoded = jwt.decode(token, { complete: true })
    if (!decoded || !decoded.header || !decoded.header.kid) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: 'jwt',
      })
    }
    const key = await this.#jwksManager.getSigningKey(decoded.header.kid)
    return jwt.verify(token, key)
  }
}
