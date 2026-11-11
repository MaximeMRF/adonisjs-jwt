import { errors } from '@adonisjs/auth'
import type { HttpContext, Redirect } from '@adonisjs/core/http'

type UnauthorizedAccess = InstanceType<typeof errors.E_UNAUTHORIZED_ACCESS>
type Renderer = (message: string, error: UnauthorizedAccess, ctx: HttpContext) => any

/**
 * Renders the 401 raised by the JWT guard, or by the `auth` middleware when
 * the JWT guard was the last one tried.
 *
 * - JSON and JSON:API requests get the same body as the `access_tokens` guard.
 * - HTML requests (pages, Inertia visits) are redirected to the login route
 *   when the `auth` middleware passes one (`loginRoute`), like the `session`
 *   guard does. Without a login route, they get a plain text 401.
 */
export const renderJwtUnauthorizedAccess: Renderer = (message, error, ctx) => {
  switch (ctx.request.accepts(['html', 'application/vnd.api+json', 'json'])) {
    case 'html':
    case null:
      if (error.redirectTo) {
        /**
         * `withIntendedUrl` is added by @adonisjs/session, which is optional
         */
        const redirect: Redirect & { withIntendedUrl?: () => unknown } = ctx.response.redirect()
        if (typeof redirect.withIntendedUrl === 'function') redirect.withIntendedUrl()
        redirect.withQs().toPath(error.redirectTo)
        return
      }
      ctx.response.status(error.status).send(message)
      return
    case 'json':
      ctx.response.status(error.status).send({ errors: [{ message }] })
      return
    case 'application/vnd.api+json':
      ctx.response.status(error.status).send({ errors: [{ code: error.code, title: message }] })
      return
  }
}

const INSTALLED = Symbol.for('@maximemrf/adonisjs-jwt/unauthorized-renderer')

/**
 * @adonisjs/auth only ships renderers for its own guards, and the `auth`
 * middleware re-throws its own `E_UNAUTHORIZED_ACCESS` with
 * `guardDriverName: 'jwt'`, so a subclass would never reach the exception
 * handler. Register the `jwt` renderer on every instance instead, unless
 * the application already registered its own.
 */
export function installJwtUnauthorizedRenderer() {
  const prototype = errors.E_UNAUTHORIZED_ACCESS.prototype as UnauthorizedAccess & {
    [INSTALLED]?: boolean
  }
  if (prototype[INSTALLED]) return

  const handle = prototype.handle
  prototype.handle = function (this: UnauthorizedAccess, error, ctx) {
    const renderers = this.renderers as Record<string, Renderer>
    if (this.guardDriverName === 'jwt' && !renderers.jwt) {
      renderers.jwt = renderJwtUnauthorizedAccess
    }
    return handle.call(this, error, ctx)
  }
  prototype[INSTALLED] = true
}
