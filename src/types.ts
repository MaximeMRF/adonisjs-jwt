import type { symbols } from '@adonisjs/auth'
import type { StringValue } from 'ms'
import type { AccessTokensUserProviderContract } from '@adonisjs/auth/types/access_tokens'
import type { Options } from 'jwks-rsa'
import type { CookieOptions } from '@adonisjs/core/types/http'
import type {
  ALLOWED_ASYMMETRIC_ALGORITHMS,
  ALLOWED_JWKS_ALGORITHMS,
  ALLOWED_SYMMETRIC_ALGORITHMS,
} from './constants.js'
import type { Secret } from '@adonisjs/core/helpers'

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
  [symbols.PROVIDER_REAL_USER]: RealUser

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

export type JwtSymmetricAlgorithm = (typeof ALLOWED_SYMMETRIC_ALGORITHMS)[number]

/**
 * Algorithms supported for asymmetric (RSA / ECDSA) JWT signing and verification.
 * Use with `privateKey` + `publicKey` so access tokens can be verified elsewhere with only the public key.
 */
export type JwtAsymmetricAlgorithm = (typeof ALLOWED_ASYMMETRIC_ALGORITHMS)[number]

export type JwtJwksAlgorithm = (typeof ALLOWED_JWKS_ALGORITHMS)[number]

/**
 * Tokens returned by `generate()` and `generateWithRefreshToken()`.
 * Lifetimes are in seconds, like `expires_in` in OAuth 2.0 (RFC 6749),
 * whatever the format used in the config (`'1h'` gives `3600`).
 * `refreshToken` and `refreshTokenExpiresIn` are set when the guard has
 * a `refreshTokenUserProvider`.
 */
export type JwtGenerateResult<WithRefreshToken extends boolean = boolean> = {
  type: 'bearer'
  token: string
  expiresIn: number
} & ([WithRefreshToken] extends [true]
  ? { refreshToken: string; refreshTokenExpiresIn: number }
  : { refreshToken?: string; refreshTokenExpiresIn?: number })

/**
 * Options shared by `jwtGuard()` and the `JwtGuard` constructor
 */
type JwtSharedOptions = {
  /**
   * Symmetric signing secret (HMAC). Used when asymmetric keys are not set.
   */
  secret?: string | Secret<string>
  /**
   * PEM-encoded private key for signing access tokens (asymmetric mode).
   */
  privateKey?: string | Secret<string>
  /**
   * PEM-encoded public key for verifying access tokens (asymmetric mode).
   */
  publicKey?: string
  /**
   * Required with `privateKey` and `publicKey`.
   */
  algorithm?: JwtAsymmetricAlgorithm
  jwks?: Options
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
   * Extra check on a verified token payload, run before looking up the user.
   * Only an explicit `true` accepts the token: any other value, or an
   * exception, rejects it. Use it to check claims other than
   * `iss` and `aud`, e.g. `client_id` and `token_use` for Amazon Cognito.
   */
  verifyPayload?: JwtVerifyPayload
}

/**
 * `content` builds the payload of the access tokens. Without `getUserId`,
 * the guard reads the user id from the `userId` claim, so `content` must
 * set it. With `getUserId`, `content` is free to use another claim.
 */
export type JwtContentOptions<RealUser> =
  | {
      /**
       * Extract the user id from a verified token payload.
       * Defaults to `payload.userId`. Use e.g. `(payload) => payload.sub` for external providers.
       */
      getUserId?: undefined
      content?: (user: JwtGuardUser<RealUser>) => Record<string, any> & BaseJwtContent
    }
  | {
      /**
       * Extract the user id from a verified token payload.
       * Defaults to `payload.userId`. Use e.g. `(payload) => payload.sub` for external providers.
       */
      getUserId: JwtGetUserId
      content?: (user: JwtGuardUser<RealUser>) => Record<string, any>
    }

/**
 * Options of the `JwtGuard` constructor
 */
export type JwtGuardOptions<RealUser = unknown> = JwtSharedOptions & {
  refreshTokenUserProvider?: AccessTokensUserProviderContract<RealUser>
} & JwtContentOptions<RealUser>

/**
 * Config accepted by `jwtGuard()` in `config/auth.ts`
 */
export type JwtGuardConfig<
  UserProvider extends JwtUserProviderContract<unknown>,
  RefreshTokenUserProvider extends AccessTokensUserProviderContract<unknown> | undefined =
    undefined,
> = JwtSharedOptions & {
  provider: UserProvider
  refreshTokenUserProvider?: RefreshTokenUserProvider
} & JwtContentOptions<UserProvider[typeof symbols.PROVIDER_REAL_USER]>

export type JwtVerifyPayload = (payload: Record<string, any>) => boolean | Promise<boolean>

export type JwtGetUserId = (
  payload: Record<string, any>
) => string | number | BigInt | undefined | null
