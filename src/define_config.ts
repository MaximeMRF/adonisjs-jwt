import { GuardConfigProvider } from '@adonisjs/auth/types'
import type { HttpContext } from '@adonisjs/core/http'
import { JwtGuard, JwtUserProviderContract } from './jwt.js'
import { Secret } from '@adonisjs/core/helpers'

export function jwtGuard<UserProvider extends JwtUserProviderContract<unknown>>(config: {
  provider: UserProvider
  tokenExpiresIn?: number | string
  useCookies?: boolean
}): GuardConfigProvider<(ctx: HttpContext) => JwtGuard<UserProvider>> {
  return {
    async resolver(_, app) {
      const appKey = (app.config.get('app.appKey') as Secret<string>).release()
      const options = {
        secret: appKey,
        expiresIn: config.tokenExpiresIn,
        useCookies: config.useCookies,
      }
      return (ctx) => new JwtGuard(ctx, config.provider, options)
    },
  }
}
