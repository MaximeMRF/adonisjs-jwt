import type { StringValue } from 'ms'

export interface JwtDriver {
  readonly canSign: boolean
  sign(payload: Record<string, any>, options?: { expiresIn?: number | StringValue }): string
  verify(token: string): Promise<Record<string, any> | string> | Record<string, any> | string
}

/**
 * Options of the `JwtGuard` constructor that are not part of the public
 * API: `jwtGuard()` resolves the driver once and passes it to every guard.
 * Custom drivers are not supported and the `JwtDriver` interface may change.
 */
export type JwtGuardInternalOptions = {
  /**
   * @internal
   */
  driver?: JwtDriver
}
