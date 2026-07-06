import type { StringValue } from 'ms'

export interface JwtDriver {
  readonly canSign: boolean
  sign(payload: Record<string, any>, options?: { expiresIn?: number | StringValue }): string
  verify(token: string): Promise<Record<string, any> | string> | Record<string, any> | string
}
