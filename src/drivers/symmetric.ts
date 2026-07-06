import jwt from 'jsonwebtoken'
import type { StringValue } from 'ms'
import type { JwtDriver } from './types.js'

export class SymmetricDriver implements JwtDriver {
  readonly canSign = true
  #secret: string

  constructor(options: { secret: string }) {
    if (!options.secret) {
      throw new Error('Symmetric JWT driver requires a secret key')
    }
    this.#secret = options.secret
  }

  sign(payload: Record<string, any>, options?: { expiresIn?: number | StringValue }): string {
    const expires = options?.expiresIn ? { expiresIn: options.expiresIn } : {}
    return jwt.sign(payload, this.#secret, expires)
  }

  verify(token: string): Record<string, any> | string {
    return jwt.verify(token, this.#secret)
  }
}
