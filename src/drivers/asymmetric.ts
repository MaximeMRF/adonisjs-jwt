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
  #clockTolerance?: number

  constructor(options: {
    privateKey: string
    publicKey: string
    algorithm: JwtAsymmetricAlgorithm
    issuer?: string
    audience?: string | string[]
    clockTolerance?: number
  }) {
    this.#privateKey = options.privateKey
    this.#publicKey = options.publicKey
    this.#algorithm = options.algorithm
    this.#issuer = options.issuer
    this.#audience = options.audience
    this.#clockTolerance = options.clockTolerance
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

    const privateKey = parseKey(createPrivateKey, this.#privateKey, 'privateKey')
    const publicKey = parseKey(createPublicKey, this.#publicKey, 'publicKey')

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

    /**
     * With keys from two different pairs, every token the guard issues
     * would be rejected by the same guard: all users would be locked out
     */
    if (!createPublicKey(privateKey).equals(publicKey)) {
      throw new Error('publicKey does not belong to the same key pair as privateKey')
    }

    /**
     * The checks above do not cover everything jsonwebtoken requires (the
     * curve of ES256/384/512, RSA keys of at least 2048 bits). Sign a token
     * now, so a bad key fails at boot instead of every login.
     */
    jwt.sign({}, this.#privateKey, { algorithm, expiresIn: 60 })
  }

  sign(payload: Record<string, any>, options: { expiresIn: number | StringValue }): string {
    const signOptions: jwt.SignOptions = {
      expiresIn: options.expiresIn,
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
      ...(this.#audience ? { audience: this.#audience as jwt.VerifyOptions['audience'] } : {}),
      ...(this.#clockTolerance !== undefined ? { clockTolerance: this.#clockTolerance } : {}),
    }
    return jwt.verify(token, this.#publicKey, verifyOptions)
  }
}

function parseKey<T>(parse: (key: string) => T, key: string, name: string): T {
  try {
    return parse(key)
  } catch (error) {
    throw new Error(
      `${name} is not a valid PEM key (${(error as Error).message}). If it comes from an env variable, replace the literal "\\n" with line breaks`
    )
  }
}
