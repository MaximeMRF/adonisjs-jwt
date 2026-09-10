import jwt from 'jsonwebtoken'
import type { StringValue } from 'ms'
import type { JwtDriver } from './types.js'
import { ALLOWED_SYMMETRIC_ALGORITHMS } from '../types.js'

export class SymmetricDriver implements JwtDriver {
  readonly canSign = true
  #secret: string
  #issuer?: string
  #audience?: string | string[]

  constructor(options: { secret: string; issuer?: string; audience?: string | string[] }) {
    if (!options.secret) {
      throw new Error('Symmetric JWT driver requires a secret key')
    }
    if (options.secret.length < 32) {
      throw new Error(
        'Symmetric JWT driver requires a secret of at least 32 characters to ensure sufficient entropy'
      )
    }
    this.#secret = options.secret
    this.#issuer = options.issuer
    this.#audience = options.audience
  }

  sign(payload: Record<string, any>, options?: { expiresIn?: number | StringValue }): string {
    const signOptions: jwt.SignOptions = {
      ...(options?.expiresIn ? { expiresIn: options.expiresIn } : {}),
      ...(this.#issuer ? { issuer: this.#issuer } : {}),
      ...(this.#audience ? { audience: this.#audience } : {}),
    }
    return jwt.sign(payload, this.#secret, signOptions)
  }

  verify(token: string): Record<string, any> | string {
    const verifyOptions: jwt.VerifyOptions = {
      algorithms: [...ALLOWED_SYMMETRIC_ALGORITHMS],
      ...(this.#issuer ? { issuer: this.#issuer } : {}),
      ...(this.#audience ? { audience: this.#audience } : {}),
    }
    return jwt.verify(token, this.#secret, verifyOptions)
  }
}
