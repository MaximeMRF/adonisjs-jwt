# Inertia and server-rendered apps

In an Inertia or server-rendered app, the pages and the API usually share the same domain. The AdonisJS [session guard](https://docs.adonisjs.com/guides/authentication/session-guard), which the starter kits configure, is then the simplest choice for the pages. A common setup keeps the session guard for the pages and adds the JWT guard for an `/api` section used by a mobile app or another service.

This page covers the other case: authenticating the pages themselves with the JWT guard, with the tokens in cookies.

## Configuration

Store both tokens in cookies, and make the JWT guard the default one:

```ts
// config/auth.ts
import app from '@adonisjs/core/services/app'
import { defineConfig } from '@adonisjs/auth'
import { sessionUserProvider } from '@adonisjs/auth/session'
import { tokensUserProvider } from '@adonisjs/auth/access_tokens'
import { jwtGuard } from '@maximemrf/adonisjs-jwt'

const authConfig = defineConfig({
  default: 'jwt',
  guards: {
    jwt: jwtGuard({
      provider: sessionUserProvider({
        model: () => import('#models/user'),
      }),
      refreshTokenUserProvider: tokensUserProvider({
        tokens: 'refreshTokens',
        model: () => import('#models/user'),
      }),
      tokenExpiresIn: '15m',
      refreshTokenExpiresIn: '7d',
      useCookies: true,
      useCookiesForRefreshToken: true,
      cookie: {
        sameSite: 'lax',
        secure: app.inProduction,
      },
    }),
  },
})
```

Keep the `session` and `shield` middleware of the starter kit: flash messages, validation errors and the [CSRF protection](https://docs.adonisjs.com/guides/security/securing-ssr-applications#csrf-protection) rely on them. Inertia forms send the CSRF token automatically.

## Log in and log out

In the starter kit controllers, replace the session login with `generate()`, which sets the cookies, and the session logout with `revoke()`:

```ts
// app/controllers/session_controller.ts
import { errors } from '@adonisjs/auth' // [!code ++]

async store({ request, auth, response }: HttpContext) {
  const { email, password } = await request.validateUsing(loginValidator)
  const user = await User.verifyCredentials(email, password)

  await auth.use('jwt').generate(user) // [!code ++]
  response.redirect().toIntendedRoute('dashboard')
}

async destroy({ auth, response }: HttpContext) {
  try { // [!code ++]
    await auth.use('jwt').revoke() // [!code ++]
  } catch (error) { // [!code ++]
    if (!(error instanceof errors.E_UNAUTHORIZED_ACCESS)) throw error // [!code ++]
  } // [!code ++]
  response.redirect().toRoute('session.create')
}
```

Do the same in the signup controller.

`revoke()` throws a `401` when the request has no valid refresh token, for example when it has expired. On a page, the user wants to be logged out anyway: the `try/catch` ignores this `401`, `revoke()` has already cleared the cookies, and the user is redirected to the login page. Without it, Inertia shows "Unauthorized access" in its error modal.

Only ignore `E_UNAUTHORIZED_ACCESS`. An empty `catch {}` would also hide a database outage: the user would be redirected as if logged out, while their refresh token stays valid, and nothing would be logged.

## Redirect to the login page

When a page requires authentication, the `auth` middleware of the starter kits passes its login route to `@adonisjs/auth`. The guard then answers like the session guard:

- page loads and Inertia visits are redirected to `/login`;
- requests that ask for JSON (`Accept: application/json`), such as a `fetch()` to an API route of the same app, get a `401` with a JSON body.

On a full page load, the URL of the page is saved as the intended URL, so `toIntendedRoute()` brings the user back to it after login. Like with the session guard, it isn't saved on Inertia visits.

## Refresh the access token on navigation

An access token lives `tokenExpiresIn`, `15m` above. Without a refresh, the user is sent back to the login page once it expires, although the refresh token is still valid. Add a middleware that exchanges the refresh token when the access token is missing or expired:

```ts
// app/middleware/jwt_refresh_middleware.ts
import { errors } from '@adonisjs/auth'
import type { HttpContext } from '@adonisjs/core/http'
import type { NextFn } from '@adonisjs/core/types/http'

export default class JwtRefreshMiddleware {
  async handle(ctx: HttpContext, next: NextFn) {
    const jwt = ctx.auth.use('jwt')
    if (!(await jwt.check())) {
      try {
        await jwt.generateWithRefreshToken() // sets the new cookies
      } catch (error) {
        // no valid refresh token: continue as a guest, the auth middleware redirects
        if (!(error instanceof errors.E_UNAUTHORIZED_ACCESS)) throw error
      }
    }
    return next()
  }
}
```

Register it in the router middleware, after `initialize_auth_middleware` and before `silent_auth_middleware`:

```ts
// start/kernel.ts
router.use([
  () => import('@adonisjs/core/bodyparser_middleware'),
  () => import('@adonisjs/session/session_middleware'),
  () => import('@adonisjs/shield/shield_middleware'),
  () => import('@adonisjs/auth/initialize_auth_middleware'),
  () => import('#middleware/jwt_refresh_middleware'), // [!code ++]
  () => import('#middleware/silent_auth_middleware'),
])
```

When the user logs out in the same request, `revoke()` revokes the refresh token that the middleware has just issued.

::: warning Concurrent requests
A refresh token can only be used once. When several requests leave with the same expired access token (prefetching, partial reloads, two tabs), only one of them refreshes it. The others are treated as unauthenticated for that request; the next one uses the new cookies. Keep this in mind for routes that must not redirect to the login page in the middle of a flow.
:::

Without this middleware, also keep the logout route outside of the `auth` middleware: once the access token has expired, the `auth` middleware would redirect to the login page before `revoke()` runs, and the refresh token would stay valid until it expires.

## Testing

Japa's `loginAs` works with the [API client](/guide/testing). The browser client (`browserContext.loginAs`) isn't supported yet: log in through the login form in browser tests.
