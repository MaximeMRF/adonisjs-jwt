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

  constructor(options: {
    privateKey: string
    publicKey: string
    algorithm: JwtAsymmetricAlgorithm
  }) {
    this.#privateKey = options.privateKey
    this.#publicKey = options.publicKey
    this.#algorithm = options.algorithm
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

    try {
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
    } catch (error) {
      const message =
        error instanceof Error ? error.message : 'Invalid asymmetric key configuration'
      throw new Error(`JwtGuard asymmetric key validation failed: ${message}`)
    }
  }

  sign(payload: Record<string, any>, options?: { expiresIn?: number | StringValue }): string {
    const expires = options?.expiresIn ? { expiresIn: options.expiresIn } : {}
    return jwt.sign(payload, this.#privateKey, {
      ...expires,
      algorithm: this.#algorithm,
    })
  }

  verify(token: string): Record<string, any> | string {
    return jwt.verify(token, this.#publicKey, {
      algorithms: [this.#algorithm],
    })
  }
}
