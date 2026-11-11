# Configuration

Register the guard in `config/auth.ts`. The smallest configuration only needs a user provider:

```ts
// config/auth.ts
import { defineConfig } from '@adonisjs/auth'
import { sessionUserProvider } from '@adonisjs/auth/session'
import { jwtGuard } from '@maximemrf/adonisjs-jwt'

const authConfig = defineConfig({
  default: 'jwt',
  guards: {
    jwt: jwtGuard({
      provider: sessionUserProvider({
        model: () => import('#models/user'),
      }),
    }),
  },
})

export default authConfig
```

With this configuration, the guard:

- signs tokens with HMAC, using a key derived from your application key (`APP_KEY`), so there is no secret to manage;
- issues access tokens that expire after **1 hour**;
- reads the token from the `Authorization: Bearer <token>` header;
- puts the user id in the token payload (`{ userId }`).

The `provider` finds users by id. `sessionUserProvider` works with any Lucid model.

## Token lifetime

`tokenExpiresIn` accepts a number of seconds or a duration string understood by [`ms`](https://github.com/vercel/ms):

```ts
jwtGuard({
  // ...
  tokenExpiresIn: '15m', // or 15 * 60
})
```

It defaults to `1h`, so access tokens always expire. A number must be positive, otherwise the guard throws at startup. Keep it short and use [refresh tokens](/guide/refresh-tokens) to keep users logged in.

## Token payload

`content` returns the payload of the access token. It receives the user wrapped by the provider, and `user.getOriginal()` is typed after your model:

```ts
jwtGuard({
  // ...
  content: (user) => ({
    userId: user.getId(),
    email: user.getOriginal().email,
  }),
})
```

The payload must contain `userId`: the guard uses it to find the user when it verifies a token. To read the user id from another claim, for example `sub`, set [`getUserId`](/reference/options#getuserid).

::: warning
Don't set `exp` in `content`, use `tokenExpiresIn`. A JWT payload is only base64 encoded, not encrypted: don't put secrets in it.
:::

## Signing key

Without `secret`, the guard derives its signing key from the application key, which must be at least 32 characters. Each guard derives its own key, so two JWT guards never accept each other's tokens. See [Security](/guide/security#signing-key) for details.

To sign with your own secret instead, for example to verify tokens in another service, set `secret`. It must be at least 32 characters:

```ts
import env from '#start/env'

jwtGuard({
  // ...
  secret: env.get('JWT_SECRET'), // generate with: openssl rand -hex 32
})
```

To sign with a key pair, see [Asymmetric signing](/guide/asymmetric). To verify tokens issued by an identity provider, see [JWKS](/guide/jwks).

## Issuer and audience

`issuer` and `audience` add the `iss` and `aud` claims to the tokens the guard signs, and reject incoming tokens that don't carry the expected values. Set them when several services share a signing key, so a token issued for one service is not accepted by another:

```ts
jwtGuard({
  // ...
  issuer: 'my-app',
  audience: 'my-api',
})
```

In [JWKS](/guide/jwks) mode, `issuer` is required, and so is `audience` unless [`verifyPayload`](/guide/jwks#check-other-claims) is set.

## Full example

A configuration with refresh tokens and cookies, next to the session guard:

```ts
// config/auth.ts
import { defineConfig } from '@adonisjs/auth'
import { sessionGuard, sessionUserProvider } from '@adonisjs/auth/session'
import { tokensUserProvider } from '@adonisjs/auth/access_tokens'
import { jwtGuard } from '@maximemrf/adonisjs-jwt'

const authConfig = defineConfig({
  default: 'jwt',
  guards: {
    web: sessionGuard({
      useRememberMeTokens: false,
      provider: sessionUserProvider({
        model: () => import('#models/user'),
      }),
    }),
    jwt: jwtGuard({
      provider: sessionUserProvider({
        model: () => import('#models/user'),
      }),
      tokenExpiresIn: '15m',
      useCookies: true,
      refreshTokenUserProvider: tokensUserProvider({
        tokens: 'refreshTokens',
        model: () => import('#models/user'),
      }),
      refreshTokenExpiresIn: '7d',
      useCookiesForRefreshToken: true,
      refreshTokenAbilities: ['refresh_token'],
      cookie: {
        sameSite: 'strict',
      },
      issuer: 'my-app',
      audience: 'my-api',
      content: (user) => ({
        userId: user.getId(),
        email: user.getOriginal().email,
      }),
    }),
  },
})

export default authConfig
```

Every option is described in the [options reference](/reference/options).
