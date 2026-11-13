import ms from 'ms'
import type { JwtGuardOptions } from './types.js'
import type { JwtGuardInternalOptions } from './drivers/types.js'

export function validateGuardOptions(
  options: ReleasedSecrets<JwtGuardOptions & JwtGuardInternalOptions>,
  prefix: string = 'JWT guard'
) {
  validateLifetimes(options, prefix)

  if (options.driver) {
    return
  }

  validateSigningMethod(options, prefix)
}

/**
 * Token lifetimes and clock tolerance. A lifetime that is not a positive
 * duration would issue tokens that are already expired (`'-1h'`), or fail
 * on every login (`'abc'`).
 */
export function validateLifetimes(
  options: Pick<JwtGuardOptions, 'tokenExpiresIn' | 'refreshTokenExpiresIn' | 'clockTolerance'>,
  prefix: string
) {
  assertDuration(options.tokenExpiresIn, 'tokenExpiresIn', prefix)
  assertDuration(options.refreshTokenExpiresIn, 'refreshTokenExpiresIn', prefix)

  if (
    options.clockTolerance !== undefined &&
    !(Number.isFinite(options.clockTolerance) && options.clockTolerance >= 0)
  ) {
    throw new Error(
      `${prefix} \`clockTolerance\` must be a number of seconds greater than or equal to 0`
    )
  }
}

function assertDuration(value: unknown, name: string, prefix: string) {
  if (value === undefined) {
    return
  }

  if (typeof value === 'number') {
    if (!(Number.isFinite(value) && value > 0)) {
      throw new Error(`${prefix} \`${name}\` must be a positive number of seconds`)
    }
    return
  }

  /**
   * A numeric string such as '3600' (read from an env variable) is parsed as
   * milliseconds by jsonwebtoken, so it is ambiguous: ask for a unit
   */
  if (typeof value !== 'string' || /^\s*[-+]?\d*\.?\d+\s*$/.test(value)) {
    throw new Error(
      `${prefix} \`${name}\` must be a number of seconds or a duration with a unit, such as '15m' or '7d' (received ${JSON.stringify(value)})`
    )
  }

  const milliseconds = ms(value as ms.StringValue) as number | undefined
  if (milliseconds === undefined || !Number.isFinite(milliseconds) || milliseconds < 1000) {
    throw new Error(
      `${prefix} \`${name}\` must be a duration of at least 1 second, such as '15m' or '7d' (received ${JSON.stringify(value)})`
    )
  }
}

/**
 * Exactly one signing method: a secret, an asymmetric key pair, or a JWKS endpoint
 */
export function validateSigningMethod(
  options: ReleasedSecrets<JwtGuardOptions>,
  prefix: string,
  { usesAppKey = false }: { usesAppKey?: boolean } = {}
) {
  const asymmetricPartial =
    options.privateKey !== undefined ||
    options.publicKey !== undefined ||
    options.algorithm !== undefined

  const usesAsymmetric =
    options.privateKey !== undefined &&
    options.publicKey !== undefined &&
    options.algorithm !== undefined

  if (asymmetricPartial && !usesAsymmetric) {
    throw new Error(
      `${prefix} asymmetric mode requires \`privateKey\`, \`publicKey\`, and \`algorithm\` to be set together`
    )
  }

  /**
   * A falsy `verifyPayload` (`null`, `false`) must not count as a payload
   * check: in JWKS mode it would replace the required `audience`
   */
  if (options.verifyPayload !== undefined && typeof options.verifyPayload !== 'function') {
    throw new Error(`${prefix} \`verifyPayload\` must be a function`)
  }

  if (options.jwks && options.refreshTokenUserProvider) {
    throw new Error(
      `${prefix} cannot use refresh tokens with \`jwks\`: tokens are issued by the identity provider, remove \`refreshTokenUserProvider\``
    )
  }

  if (options.secret !== undefined && typeof options.secret !== 'string') {
    throw new Error(`${prefix} \`secret\` must be a string or a Secret`)
  }

  /**
   * In JWKS mode, the driver checks them with its own message. Elsewhere,
   * an empty value is signed into every token, then rejects all of them.
   */
  if (!options.jwks) {
    if (options.issuer !== undefined && !isNonEmptyString(options.issuer)) {
      throw new Error(`${prefix} \`issuer\` must be a non-empty string`)
    }
    if (
      options.audience !== undefined &&
      !(Array.isArray(options.audience)
        ? options.audience.length > 0 && options.audience.every(isNonEmptyString)
        : isNonEmptyString(options.audience))
    ) {
      throw new Error(`${prefix} \`audience\` must be a non-empty string or array of strings`)
    }
  }

  if (options.jwks && usesAsymmetric) {
    throw new Error(
      `${prefix} cannot use \`jwks\` together with asymmetric \`privateKey\` / \`publicKey\``
    )
  }

  if (
    options.jwks &&
    !(typeof options.jwks.jwksUri === 'string' && options.jwks.jwksUri.trim() !== '')
  ) {
    throw new Error(`${prefix} \`jwks.jwksUri\` is required to fetch the identity provider keys`)
  }

  /**
   * Without a signing method, `jwtGuard()` derives the secret from the app
   * key in the resolver
   */
  if (!usesAppKey && !options.jwks && !usesAsymmetric && !options.secret) {
    throw new Error(
      `${prefix} requires \`secret\` (symmetric), or \`privateKey\` + \`publicKey\` + \`algorithm\` (asymmetric), or \`jwks\``
    )
  }
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim() !== ''
}

/**
 * Accept `Secret` values (`Env.schema.secret()` in AdonisJS v7) for the
 * signing keys, and work with their string value
 */
export type ReleasedSecrets<Options> = Options extends any
  ? Omit<Options, 'secret' | 'privateKey'> & { secret?: string; privateKey?: string }
  : never

export function releaseSecrets<Options extends { secret?: unknown; privateKey?: unknown }>(
  options: Options
): ReleasedSecrets<Options> {
  return {
    ...options,
    ...(options.secret !== undefined ? { secret: release(options.secret) } : {}),
    ...(options.privateKey !== undefined ? { privateKey: release(options.privateKey) } : {}),
  } as unknown as ReleasedSecrets<Options>
}

function release(value: unknown) {
  return value && typeof (value as { release?: unknown }).release === 'function'
    ? (value as { release(): unknown }).release()
    : value
}

/**
 * A lifetime from the config (a number of seconds or a `ms` duration such
 * as `'1h'`), as a whole number of seconds. Lifetimes are validated first.
 */
export function toSeconds(value: number | string): number {
  return Math.floor(typeof value === 'number' ? value : ms(value as ms.StringValue) / 1000)
}
