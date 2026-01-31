import { symbols } from '@adonisjs/auth'
import type { StringValue } from 'ms'
import { AccessTokensUserProviderContract } from '@adonisjs/auth/types/access_tokens'
import { Options } from 'jwks-rsa'

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

export type JwtGuardOptions<RealUser extends any = unknown> = {
  secret: string
  jwks?: Options
  refreshTokenUserProvider?: AccessTokensUserProviderContract<RealUser>
  tokenName?: string
  expiresIn?: number | StringValue
  refreshTokenExpiresIn?: number | StringValue
  useCookies?: boolean
  useCookiesForRefreshToken?: boolean
  refreshTokenAbilities?: string[]
  content?: (user: JwtGuardUser<RealUser>) => Record<string, any>
}
