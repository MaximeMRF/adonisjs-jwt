import { type symbols } from '@adonisjs/auth'
import type { StringValue } from 'ms'
import type { AccessTokensUserProviderContract } from '@adonisjs/auth/types/access_tokens'
import type { Options } from 'jwks-rsa'
import type { CookieOptions } from '@adonisjs/core/types/http'
import type { JwtDriver } from './drivers/types.js'

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
 * Lifetime of access tokens when `tokenExpiresIn` is not configured
 */
export const DEFAULT_TOKEN_EXPIRES_IN = '1h'

export const ALLOWED_SYMMETRIC_ALGORITHMS = ['HS256', 'HS384', 'HS512'] as const
export type JwtSymmetricAlgorithm = (typeof ALLOWED_SYMMETRIC_ALGORITHMS)[number]

export const ALLOWED_ASYMMETRIC_ALGORITHMS = [
  'RS256',
  'RS384',
  'RS512',
  'ES256',
  'ES384',
  'ES512',
] as const

/**
 * Algorithms supported for asymmetric (RSA / ECDSA) JWT signing and verification.
 * Use with `privateKey` + `publicKey` so access tokens can be verified elsewhere with only the public key.
 */
export type JwtAsymmetricAlgorithm = (typeof ALLOWED_ASYMMETRIC_ALGORITHMS)[number]

export const ALLOWED_JWKS_ALGORITHMS = [
  ...ALLOWED_ASYMMETRIC_ALGORITHMS,
  'PS256',
  'PS384',
  'PS512',
] as const

export type JwtJwksAlgorithm = (typeof ALLOWED_JWKS_ALGORITHMS)[number]

export type JwtGenerateResult = {
  type: string
  token: string
  expiresIn?: number | StringValue
  refreshToken?: string
  refreshTokenExpiresIn?: number | StringValue
}

export type JwtGuardOptions<RealUser extends any = unknown> = {
  /**
   * Driver resolved by `jwtGuard()`. Not part of the public API: custom
   * drivers are not supported and the `JwtDriver` interface may change.
   */
  driver?: JwtDriver
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
  /**
   * Name of the refresh token cookie and request body field.
   * Defaults to `refreshToken`.
   */
  refreshTokenName?: string
  /**
   * Lifetime of access tokens. Defaults to `DEFAULT_TOKEN_EXPIRES_IN`.
   */
  tokenExpiresIn?: number | StringValue
  refreshTokenExpiresIn?: number | StringValue
  useCookies?: boolean
  useCookiesForRefreshToken?: boolean
  /**
   * Abilities given to refresh tokens. When set, `generateWithRefreshToken`
   * rejects refresh tokens that don't have all of them.
   */
  refreshTokenAbilities?: string[]
  cookie?: JwtCookieOptions
  content?: (user: JwtGuardUser<RealUser>) => Record<string, any> & BaseJwtContent
  /**
   * Expected JWT issuer (iss). Validated during token verification.
   * Required in JWKS mode.
   */
  issuer?: string
  /**
   * Expected JWT audience (aud). Validated during token verification.
   * Required in JWKS mode, unless `verifyPayload` is set.
   */
  audience?: string | string[]
  /**
   * Algorithms accepted when verifying tokens in JWKS mode.
   * Must be a non-empty subset of `ALLOWED_JWKS_ALGORITHMS` (default: all of them).
   */
  algorithms?: JwtJwksAlgorithm[]
  /**
   * Number of seconds of clock skew tolerated when checking `exp` / `nbf`.
   */
  clockTolerance?: number
  /**
   * Extract the user id from a verified token payload.
   * Defaults to `payload.userId`. Use e.g. `(payload) => payload.sub` for external providers.
   */
  getUserId?: JwtGetUserId
  /**
   * Extra check on a verified token payload, run before looking up the user.
   * Return `false` to reject the token. Use it to check claims other than
   * `iss` and `aud`, e.g. `client_id` and `token_use` for Amazon Cognito.
   */
  verifyPayload?: JwtVerifyPayload
}

export type JwtVerifyPayload = (payload: Record<string, any>) => boolean | Promise<boolean>

export type JwtGetUserId = (
  payload: Record<string, any>
) => string | number | BigInt | undefined | null
