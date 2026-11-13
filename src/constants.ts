/**
 * Lifetime of access tokens when `tokenExpiresIn` is not configured
 */
export const DEFAULT_TOKEN_EXPIRES_IN = '1h'

/**
 * Lifetime of refresh tokens when `refreshTokenExpiresIn` is not configured
 */
export const DEFAULT_REFRESH_TOKEN_EXPIRES_IN = '7d'

export const ALLOWED_SYMMETRIC_ALGORITHMS = ['HS256', 'HS384', 'HS512'] as const

export const ALLOWED_ASYMMETRIC_ALGORITHMS = [
  'RS256',
  'RS384',
  'RS512',
  'ES256',
  'ES384',
  'ES512',
] as const

export const ALLOWED_JWKS_ALGORITHMS = [
  ...ALLOWED_ASYMMETRIC_ALGORITHMS,
  'PS256',
  'PS384',
  'PS512',
] as const
