import { symbols } from '@adonisjs/auth'
import type { StringValue } from 'ms'
import type { AccessTokensUserProviderContract } from '@adonisjs/auth/types/access_tokens'
import type { Options } from 'jwks-rsa'
import type { CookieOptions } from '@adonisjs/core/types/http'

export type JwtCookieOptions = Omit<Partial<CookieOptions>, 'maxAge' | 'expires'>

/**
 * The bridge between the User provider and the
 * Guard
 */
export type JwtGuardUser<RealUser> = {
  /**
   * Returns the unique ID of the user
   */
  getId(): string | number | BigInt

  /**
   * Returns the original user object
   */
  getOriginal(): RealUser
}

/**
 * The interface for the UserProvider accepted by the
 * JWT guard.
 */
export interface JwtUserProviderContract<RealUser> {
  /**
   * A property the guard implementation can use to infer
   * the data type of the actual user (aka RealUser)
   */
  [symbols.PROVIDER_REAL_USER]?: RealUser

  /**
   * Create a user object that acts as an adapter between
   * the guard and real user value.
   */
  createUserForGuard(user: RealUser): Promise<JwtGuardUser<RealUser>>

  /**
   * Find a user by their id.
   */
  findById(identifier: string | number | BigInt): Promise<JwtGuardUser<RealUser> | null>
}

export type BaseJwtContent = {
  userId: string | number | BigInt
}

/**
 * Algorithms supported for asymmetric (RSA / ECDSA) JWT signing and verification.
 * Use with `privateKey` + `publicKey` so access tokens can be verified elsewhere with only the public key.
 */
export type JwtAsymmetricAlgorithm = 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512'

export type JwtGuardOptions<RealUser extends any = unknown> = {
  /**
   * Symmetric signing secret (HMAC). Used when asymmetric keys are not set.
   */
  secret?: string
  /**
   * PEM-encoded private key for signing access tokens (asymmetric mode).
   */
  privateKey?: string
  /**
   * PEM-encoded public key for verifying access tokens (asymmetric mode).
   */
  publicKey?: string
  /**
   * Required with `privateKey` and `publicKey`.
   */
  algorithm?: JwtAsymmetricAlgorithm
  jwks?: Options
  refreshTokenUserProvider?: AccessTokensUserProviderContract<RealUser>
  tokenName?: string
  expiresIn?: number | StringValue
  refreshTokenExpiresIn?: number | StringValue
  useCookies?: boolean
  useCookiesForRefreshToken?: boolean
  refreshTokenAbilities?: string[]
  cookie?: JwtCookieOptions
  content?: (user: JwtGuardUser<RealUser>) => Record<string, any>
}
