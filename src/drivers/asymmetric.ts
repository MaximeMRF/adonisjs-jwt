import jwt from 'jsonwebtoken'
import type { StringValue } from 'ms'
import { createPrivateKey, createPublicKey } from 'node:crypto'
import type { JwtDriver } from './types.js'
import type { JwtAsymmetricAlgorithm } from '../types.js'

export class AsymmetricDriver implements JwtDriver {
  readonly canSign = true
  #privateKey: string
  #publicKey: string
  #algorithm: JwtAsymmetricAlgorithm
  #issuer?: string
  #audience?: string | string[]

  constructor(options: {
    privateKey: string
    publicKey: string
    algorithm: JwtAsymmetricAlgorithm
    issuer?: string
    audience?: string | string[]
  }) {
    this.#privateKey = options.privateKey
    this.#publicKey = options.publicKey
    this.#algorithm = options.algorithm
    this.#issuer = options.issuer
    this.#audience = options.audience
    this.#assertAsymmetricKeyMatchesAlgorithm()
  }

  #assertAsymmetricKeyMatchesAlgorithm() {
    const algorithm = this.#algorithm
    const expectedKeyType = algorithm.startsWith('RS')
      ? 'rsa'
      : algorithm.startsWith('ES')
        ? 'ec'
        : null

    if (!expectedKeyType) {
      throw new Error(`Unsupported asymmetric algorithm "${algorithm}"`)
    }

    const privateKey = createPrivateKey(this.#privateKey)
    const publicKey = createPublicKey(this.#publicKey)

    if (privateKey.asymmetricKeyType !== expectedKeyType) {
      throw new Error(
        `privateKey type "${privateKey.asymmetricKeyType}" does not match algorithm "${algorithm}"`
      )
    }

    if (publicKey.asymmetricKeyType !== expectedKeyType) {
      throw new Error(
        `publicKey type "${publicKey.asymmetricKeyType}" does not match algorithm "${algorithm}"`
      )
    }
  }

  sign(payload: Record<string, any>, options?: { expiresIn?: number | StringValue }): string {
    const signOptions: jwt.SignOptions = {
      ...(options?.expiresIn ? { expiresIn: options.expiresIn } : {}),
      algorithm: this.#algorithm,
      ...(this.#issuer ? { issuer: this.#issuer } : {}),
      ...(this.#audience ? { audience: this.#audience } : {}),
    }
    return jwt.sign(payload, this.#privateKey, signOptions)
  }

  verify(token: string): Record<string, any> | string {
    const verifyOptions: jwt.VerifyOptions = {
      algorithms: [this.#algorithm],
      ...(this.#issuer ? { issuer: this.#issuer } : {}),
      ...(this.#audience ? { audience: this.#audience } : {}),
    }
    return jwt.verify(token, this.#publicKey, verifyOptions)
  }
}
