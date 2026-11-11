import ms from 'ms'
import type { JwtGuardOptions } from './types.js'

export function validateGuardOptions(options: JwtGuardOptions, prefix: string = 'JwtGuard') {
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
export function validateSigningMethod(options: JwtGuardOptions, prefix: string) {
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

  if (!options.jwks && !usesAsymmetric && !options.secret) {
    throw new Error(
      `${prefix} requires \`secret\` (symmetric), or \`privateKey\` + \`publicKey\` + \`algorithm\` (asymmetric), or \`jwks\``
    )
  }
}
