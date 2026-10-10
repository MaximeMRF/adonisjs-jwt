# Authentication

## Issue a token

Verify the user's credentials, then call `generate()`:

```ts
// start/routes.ts
import router from '@adonisjs/core/services/router'
import User from '#models/user'

router.post('login', async ({ request, auth }) => {
  const { email, password } = request.only(['email', 'password'])
  const user = await User.verifyCredentials(email, password)

  return await auth.use('jwt').generate(user)
})
```

`generate()` returns:

```json
{
  "type": "bearer",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": "1h",
  "refreshToken": "rt_MQ.xxxxxxxx",
  "refreshTokenExpiresIn": "7d"
}
```

`refreshToken` and `refreshTokenExpiresIn` are only set when [refresh tokens](/guide/refresh-tokens) are configured. With [cookies](/guide/token-transport) enabled, `generate()` also sets the tokens as cookies on the response.

::: tip
`User.verifyCredentials` comes from the `withAuthFinder` mixin of `@adonisjs/auth`. See [Verifying user credentials](https://docs.adonisjs.com/guides/authentication/verifying-user-credentials).
:::

## Protect routes

Use the `auth` middleware. If `jwt` is the default guard:

```ts
import { middleware } from '#start/kernel'

router
  .get('me', async ({ auth }) => {
    return auth.getUserOrFail()
  })
  .use(middleware.auth())
```

Otherwise, name the guard:

```ts
router
  .get('me', async ({ auth }) => {
    return auth.use('jwt').getUserOrFail()
  })
  .use(middleware.auth({ guards: ['jwt'] }))
```

The client sends the token in the `Authorization` header:

```http
GET /me HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

A missing, expired or invalid token is rejected with an `E_UNAUTHORIZED_ACCESS` error, which AdonisJS turns into a `401` response.

## Optional authentication

To know whether a request is authenticated without rejecting it, use `check()`:

```ts
router.get('posts', async ({ auth }) => {
  if (await auth.use('jwt').check()) {
    // auth.use('jwt').user is set
  }
})
```

## Current token

After `authenticate()`, the access token of the request is available as `user.currentToken`, like `user.currentAccessToken` with the AdonisJS access tokens guard:

```ts
const user = auth.use('jwt').getUserOrFail()
user.currentToken // the JWT sent by the client
```

After [`generateWithRefreshToken()`](/guide/refresh-tokens), it holds the new access token.

## Log out

Access tokens are stateless: they stay valid until they expire. Logging out revokes the refresh token and clears the cookies set by the guard, see [Revoking tokens](/guide/refresh-tokens#revoke-a-refresh-token).
