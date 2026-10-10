<p align="center">
  <img src="https://maximemax.sirv.com/npm_package_maxime_jwt.png" alt="@maximemrf/adonisjs-jwt">
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@maximemrf/adonisjs-jwt"><img src="https://img.shields.io/npm/dm/@maximemrf/adonisjs-jwt.svg?style=flat-square" alt="Download"></a>
  <a href="https://www.npmjs.com/package/@maximemrf/adonisjs-jwt"><img src="https://img.shields.io/npm/v/@maximemrf/adonisjs-jwt.svg?style=flat-square" alt="Version"></a>
  <a href="https://www.npmjs.com/package/@maximemrf/adonisjs-jwt"><img src="https://img.shields.io/npm/last-update/@maximemrf/adonisjs-jwt.svg?style=flat-square" alt="NPM Last Update"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/npm/l/@maximemrf/adonisjs-jwt.svg?style=flat-square" alt="License"></a>
  <a href="https://adonisjs.com/"><img src="https://img.shields.io/badge/AdonisJS-v6-5A45FF.svg?style=flat-square" alt="AdonisV6"></a>
  <a href="https://adonisjs.com/"><img src="https://img.shields.io/badge/AdonisJS-v7-5A45FF.svg?style=flat-square" alt="AdonisV7"></a>
</p>

> AdonisJS package to authenticate users using JWT tokens.

## Compatibility & Versions

| Package Version | AdonisJS Version  | Node.js Required |
| --------------- | ----------------- | ---------------- |
| `v0.7.x`        | `AdonisJS v6`     | `>= 20.6.0`      |
| **`>= v0.8.x`**    | **`AdonisJS v7`** | **`>= 24.0.0`**  |

## Upgrading to 1.0

Version 1.0 contains breaking changes. Check this list before upgrading from `0.9.x`:

- **Signing key**: without a `secret`, tokens are now signed with a key derived from the application key instead of the raw application key, and the application key must be at least 32 characters. Access tokens issued by `0.9.x` are rejected, so users have to log in again or use their refresh token, which stays valid. See [Security](#security).
- **Default expiration**: `tokenExpiresIn` defaults to `1h`. A `content` function that sets `exp` itself now fails, use `tokenExpiresIn` instead.
- **JWKS**: `issuer` and `audience` are required, the guard throws at startup if one of them is missing. See [JWKS](#jwks).
- **Refresh token in the query string**: it is ignored, send it in the body, a cookie or the `Authorization` header.
- **Refresh token body field**: the field follows `refreshTokenName`. If you set a custom `refreshTokenName` and your clients send the token in a `refreshToken` body field, rename that field to match `refreshTokenName`.
- **Refresh token lookup order**: when `useCookiesForRefreshToken` is enabled, the cookie is now read before the request body. See [Refresh token transport](#refresh-token-transport).
- **Access token lookup order**: the `Authorization` header is now read before the cookie, and the cookie is only read when `useCookies` is enabled. If you set the `token` cookie yourself without `useCookies`, enable `useCookies`.
- **`JwtGuardOptions.expiresIn`** is renamed to `tokenExpiresIn`, like the `jwtGuard()` option. This only affects code that instantiates `JwtGuard` directly.

Imports can now come from the main entrypoint: `import { jwtGuard } from '@maximemrf/adonisjs-jwt'`. The `@maximemrf/adonisjs-jwt/jwt_config` path still works. `@adonisjs/auth` is now a peer dependency.

## Prerequisites

You have to install the auth package from AdonisJS

```bash
node ace add @adonisjs/auth
```

## Setup (AdonisJS v7)

Install the package:

```bash
npm i @maximemrf/adonisjs-jwt
```

## Setup for AdonisJS v6

If you are using AdonisJS v6, you have to install the `v0.7.x` version of the package:

```bash
npm i @maximemrf/adonisjs-jwt@0.7.1
```

## Usage

Go to `config/auth.ts` and add the following configuration:

```typescript
import { defineConfig } from '@adonisjs/auth'
import { InferAuthEvents, Authenticators } from '@adonisjs/auth/types'
import { sessionGuard, sessionUserProvider } from '@adonisjs/auth/session'
import { tokensUserProvider } from '@adonisjs/auth/access_tokens'
import { jwtGuard } from '@maximemrf/adonisjs-jwt'
import env from '#start/env'

const authConfig = defineConfig({
  // define the default authenticator to jwt
  default: 'jwt',
  guards: {
    web: sessionGuard({
      useRememberMeTokens: false,
      provider: sessionUserProvider({
        model: () => import('#models/user'),
      }),
    }),
    // add the jwt guard
    jwt: jwtGuard({
      // tokenName is the name of the token passed as cookie, it can be optional, by default it is 'token'
      tokenName: 'custom-name',
      // tokenExpiresIn can be a string or a number, it can be optional, by default it is '1h'
      tokenExpiresIn: '1h',
      // if you want to use cookies for the authentication instead of the bearer token (optional)
      useCookies: true,
      // secret is the secret used to sign the token, it can be optional, by default a key derived from the application key is used
      // you can use a env variable like JWT_SECRET or set it directly with a string
      // if you don't have specific needs, please discard this option
      secret: env.get('JWT_SECRET'),
      provider: sessionUserProvider({
        model: () => import('#models/user'),
      }),
      // if you want to use refresh tokens, you have to set the refreshTokenUserProvider
      refreshTokenUserProvider: tokensUserProvider({
        tokens: 'refreshTokens',
        model: () => import('#models/user'),
      }),
      // optionally set the expiry for the refresh token
      refreshTokenExpiresIn: '7d',
      // ability to separate cookie usage for refresh token
      useCookiesForRefreshToken: true,
      // ability to configure the cookies options
      cookie: {
        httpOnly: true,
        secure: true,
      },
      // abilities given to refresh tokens, generateWithRefreshToken rejects tokens that don't have all of them
      refreshTokenAbilities: ['refresh_token'],
      // optional issuer (iss) and audience (aud) claims for token verification
      issuer: 'my-app',
      audience: 'my-api',
      // content is a function that takes the user and returns the content of the token, it can be optional, by default it returns only the user id
      // user.getOriginal() is typed after the provider's model, no cast needed
      content: (user) => {
        return {
          userId: user.getId(),
          email: user.getOriginal().email,
        }
      },
    }),
  },
})
```

`tokenName` is the name of the jwt token passed as a cookie, it can be optional, by default it is `token`.
`refreshTokenName` is the name of the refresh token cookie and of the request body field the guard reads it from, by default it is `refreshToken`.
`issuer` and `audience` allow validating the `iss` and `aud` claims on incoming tokens to prevent cross-service token misuse in multi-service architecture.

```typescript
tokenName: 'custom-name'
```

`tokenExpiresIn` is the time before the jwt token expires, it can be a string or a number (in seconds) and it can be optional. It defaults to `1h`, so access tokens always expire. A number must be positive, otherwise the guard throws at startup.

```typescript
// string
tokenExpiresIn: '1h'
// number
tokenExpiresIn: 60 * 60
```

You can also use cookies for the authentication instead of the bearer token by setting `useCookies` to `true`.

```typescript
useCookies: true
```

If you just want to use jwt with the bearer token no need to set `useCookies` to `false` you can just remove it.

The guard reads the access token from the `Authorization: Bearer <token>` header first, then from the cookie when `useCookies` is enabled. A stale cookie therefore never shadows a valid bearer token, and the cookie is ignored when `useCookies` is disabled.

You can also pass options to the cookies. Note that `maxAge` and `expires` are omitted from the options because they are automatically handled by the package based on the token validity (`tokenExpiresIn` and `refreshTokenExpiresIn`).
By default, `httpOnly: true` and `secure: true` are enforced for better security, but you can override them using the `cookie` object configuration.

```typescript
cookie: {
  httpOnly: true, // Default
  secure: true,   // Default
  path: '/',
  sameSite: 'lax',
  // maxAge and expires cannot be set here
}
```

## Asymmetric signing (RSA / ECDSA)

You can sign access tokens with a **private key** and verify them with a **public key** only. Other services can validate JWTs using the public key without receiving your signing secret.

Set `privateKey`, `publicKey`, and `algorithm` together on `jwtGuard`. Supported algorithms: `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`.

Do not set `secret` for this mode (the guard resolver omits it when asymmetric keys are configured). Asymmetric signing cannot be combined with `jwks`.

```typescript
import env from '#start/env'

jwt: jwtGuard({
  tokenExpiresIn: '15m',
  privateKey: env.get('JWT_PRIVATE_KEY').replace(/\\n/g, '\n'),
  publicKey: env.get('JWT_PUBLIC_KEY').replace(/\\n/g, '\n'),
  algorithm: 'RS256',
  content: (user) => ({ userId: user.getId() }),
  provider: sessionUserProvider({
    model: () => import('#models/user'),
  }),
}),
```

## JWKS

You can use JWKS to verify the token by setting the `jwks` option in the guard configuration.

```typescript
// ...
jwt: jwtGuard({
  // ...
  jwks: {
    jwksUri: 'https://your-auth-server/.well-known/jwks.json',
    // you can pass any options accepted by jwks-rsa package
  },
  // required in JWKS mode
  issuer: 'https://your-auth-server',
  audience: 'my-api',
}),
// ...
```

`issuer` and `audience` are required in JWKS mode: the guard throws at startup if one of them is missing.

Tokens with an unknown `kid` trigger a JWKS fetch, so the guard applies these jwks-rsa defaults, which you can override in the `jwks` option: `cache: true`, `rateLimit: true`, `jwksRequestsPerMinute: 10` and `timeout: 5000` (ms).

> [!WARNING]
> If you enable JWKS, you cannot use the `auth.use('jwt').generate(user)` and `auth.use('jwt').generateWithRefreshToken()` method because the token is signed by an external provider. You can only use the `authenticate` (or `check` / `getUserOrFail`) method to verify the token.

Tokens issued by an external provider usually don't carry a `userId` claim. Use `getUserId` to tell the guard where to find the user id, and `algorithms` to restrict the accepted signing algorithms (default: every asymmetric algorithm supported in JWKS mode; symmetric `HS*` algorithms are never accepted):

```typescript
jwt: jwtGuard({
  // ...
  jwks: {
    jwksUri: 'https://your-auth-server/.well-known/jwks.json',
  },
  issuer: 'https://your-auth-server',
  audience: 'my-api',
  algorithms: ['RS256'],
  // seconds of clock skew tolerated on `exp` / `nbf` (optional, works in every mode)
  clockTolerance: 30,
  // default: (payload) => payload.userId
  getUserId: (payload) => payload.sub,
}),
```

> [!WARNING]
> `audience` and `issuer` are required in JWKS mode. Without them, **any** token signed by the identity provider would be accepted, including tokens issued for other applications. With Kubernetes, that means every pod's default ServiceAccount token.

### Example: Kubernetes ServiceAccount tokens

The Kubernetes API server exposes its signing keys at `https://kubernetes.default.svc/openid/v1/jwks`. From inside the cluster, fetching them requires the cluster CA and a ServiceAccount token, which you can provide with a custom jwks-rsa `fetcher` (the token is re-read on each fetch because projected tokens are rotated):

```typescript
import { readFileSync } from 'node:fs'
import https from 'node:https'

const SA_DIR = '/var/run/secrets/kubernetes.io/serviceaccount'

jwt: jwtGuard({
  // findById receives the token `sub`, e.g. "system:serviceaccount:my-namespace:my-sa"
  provider: new ServiceAccountUserProvider(),
  jwks: {
    jwksUri: 'https://kubernetes.default.svc/openid/v1/jwks',
    cache: true,
    fetcher: (uri) =>
      new Promise((resolve, reject) => {
        https
          .get(
            uri,
            {
              ca: readFileSync(`${SA_DIR}/ca.crt`),
              headers: { Authorization: `Bearer ${readFileSync(`${SA_DIR}/token`, 'utf8')}` },
            },
            (res) => {
              let body = ''
              res.on('data', (chunk) => (body += chunk))
              res.on('end', () => {
                if (res.statusCode !== 200) {
                  return reject(new Error(`JWKS fetch failed with status ${res.statusCode}`))
                }
                resolve(JSON.parse(body))
              })
            }
          )
          .on('error', reject)
      }),
  },
  // must match the `audiences` of the projected token mounted in the calling pods
  audience: 'my-api',
  // default issuer on kubeadm-based clusters; managed clusters use their own URL (see below)
  issuer: 'https://kubernetes.default.svc.cluster.local',
  getUserId: (payload) => payload.sub,
}),
```

The issuer depends on your cluster: `https://kubernetes.default.svc.cluster.local` is the kubeadm default, while managed clusters use their own URL (e.g. `https://oidc.eks.<region>.amazonaws.com/id/<id>` on EKS, `https://container.googleapis.com/v1/projects/<project>/locations/<location>/clusters/<cluster>` on GKE). Check yours with:

```bash
kubectl get --raw /.well-known/openid-configuration
```

Legacy Secret-based ServiceAccount tokens (issuer `kubernetes/serviceaccount`, no expiration) are rejected by the `issuer` check.

The calling pod mounts a projected token with that audience and sends it as a Bearer token:

```yaml
spec:
  containers:
    - name: my-client
      volumeMounts:
        - name: api-token
          mountPath: /var/run/secrets/my-api
          readOnly: true
  volumes:
    - name: api-token
      projected:
        sources:
          - serviceAccountToken:
              path: token
              audience: my-api
              expirationSeconds: 3600
```

The kubelet rotates this token before it expires, so the client must re-read `/var/run/secrets/my-api/token` on each request (or at least regularly) instead of caching it at startup.

> [!NOTE]
> Tokens are verified offline against the JWKS, not through the Kubernetes `TokenReview` API. A token stays valid until its `exp` even if the pod it was issued for has been deleted (up to `expirationSeconds`, minimum 600). Keep `expirationSeconds` short, or call `TokenReview` from your user provider if you need immediate revocation.

## Refresh Tokens

To use refresh tokens, you have to set the `refreshTokenUserProvider` in the guard configuration, see the example above.

Create a new AdonisJS migration file and run it to create the `jwt_refresh_tokens` table:

```typescript
import { BaseSchema } from '@adonisjs/lucid/schema'

export default class extends BaseSchema {
  protected tableName = 'jwt_refresh_tokens'

  async up() {
    this.schema.createTable(this.tableName, (table) => {
      table.increments()
      table
        .integer('tokenable_id')
        .notNullable()
        .unsigned()
        .references('id')
        .inTable('users')
        .onDelete('CASCADE')
      table.string('type').notNullable()
      table.string('name').nullable()
      table.string('hash', 80).notNullable()
      table.text('abilities').notNullable()
      table.timestamp('created_at', { precision: 6, useTz: true }).notNullable()
      table.timestamp('updated_at', { precision: 6, useTz: true }).notNullable()
      table.timestamp('expires_at', { precision: 6, useTz: true }).nullable()
      table.timestamp('last_used_at', { precision: 6, useTz: true }).nullable()
    })
  }

  async down() {
    this.schema.dropTable(this.tableName)
  }
}
```

And add the `refreshTokens` property to your User model:

```typescript
import { column, BaseModel } from '@adonisjs/lucid/orm'
import { DbAccessTokensProvider } from '@adonisjs/auth/access_tokens'

export default class User extends BaseModel {
  @column({ isPrimary: true })
  declare id: number

  @column()
  declare username: string

  @column()
  declare email: string

  @column()
  declare password: string

  static refreshTokens = DbAccessTokensProvider.forModel(User, {
    prefix: 'rt_',
    table: 'jwt_refresh_tokens',
    type: 'jwt_refresh_token',
    tokenSecretLength: 40,
  })
}
```

## Authentication

To make a protected route, you have to use the `auth` middleware with the `jwt` guard.

```typescript
router.post('login', async ({ request, auth }) => {
  const { email, password } = request.all()
  const user = await User.verifyCredentials(email, password)

  // to generate a token (and refresh token if configured)
  // this returns { type, token, expiresIn, refreshToken, refreshTokenExpiresIn }
  // if useCookies is true, it sets cookies on the response instead
  return await auth.use('jwt').generate(user)
})

// if the jwt guard is the default guard
router
  .get('/', async ({ auth }) => {
    return auth.getUserOrFail()
  })
  .use(middleware.auth())

// if the jwt guard is not the default guard
router
  .get('/', async ({ auth }) => {
    return auth.use('jwt').getUserOrFail()
  })
  .use(middleware.auth({ guards: ['jwt'] }))

// if you use the refresh token
router.post('jwt/refresh', async ({ auth }) => {
  // this will authenticate the user using the refresh token
  // it will delete the old refresh token and generate a new one
  // it accepts an optional refresh token, otherwise it looks in:
  // 1. cookies (if useCookiesForRefreshToken is enabled)
  // 2. request body, field named after refreshTokenName (never the query string)
  // 3. Authorization header
  return await auth.use('jwt').generateWithRefreshToken()
})

// to logout (revoke refresh token and clear the guard cookies)
router.post('logout', async ({ auth }) => {
  await auth.use('jwt').revoke()
  return { message: 'Logged out' }
})
```

After `authenticate()` or `generateWithRefreshToken()`, the access token of the request is available as `user.currentToken`, like `user.currentAccessToken` with the AdonisJS access tokens guard. After a refresh, it holds the new access token.

## Security

When no `secret` is configured, the guard signs tokens with a key derived from the AdonisJS application key (HKDF-SHA256, salted with the guard name), so you don't have to manage a secret and [avoid this](https://trufflesecurity.com/blog/stop-recommending-jwts). The raw application key is never used to sign JWTs, so tokens signed elsewhere with the application key (e.g. password reset links) are not accepted as access tokens, and two JWT guards never accept each other's tokens. The application key must be at least 32 characters.

> [!NOTE]
> Tokens issued before this key derivation was introduced (signed with the raw application key) are no longer accepted: users have to log in again, or use their refresh token, which is stored in the database and stays valid.

### Refresh token transport

The guard reads the refresh token from these sources, in order:

1. An `HttpOnly` cookie named after `refreshTokenName`, when `useCookiesForRefreshToken` is enabled.
2. The request body, in a field named after `refreshTokenName` (`refreshToken` by default). This is how OAuth 2.0 transmits refresh tokens ([RFC 6749 §6](https://datatracker.ietf.org/doc/html/rfc6749#section-6)).
3. The `Authorization: Bearer <token>` header.

A refresh token passed in the query string is ignored, since URLs end up in access logs, browser history and `Referer` headers.

> [!IMPORTANT]
> **Breaking change in 1.0**: the body field used to be `refreshToken` whatever `refreshTokenName` was set to, and the body was read before the cookie. If you set a custom `refreshTokenName`, your clients must now send the token in a body field with that name.

Which transport to pick:

- **Browsers**: use cookies (`useCookiesForRefreshToken: true`). The token is stored in an `HttpOnly` + `Secure` cookie, out of reach of JavaScript and scoped by the `SameSite` policy.
- **Mobile apps, CLIs and other API clients**: send the token in the request body or the `Authorization` header.

> [!WARNING]
> Make sure your logging middleware does not record request bodies or `Authorization` headers on authentication routes, otherwise refresh tokens end up in plain text in your logs.

### Symmetric secret strength

When using symmetric signing (HMAC), the `secret` must be **at least 32 characters** long. A shorter secret can be brute-forced offline once an attacker obtains a signed token.

```
// Too short — will throw at startup
secret: 'mysecret'

// Sufficient entropy
secret: env.get('JWT_SECRET') // generate with: openssl rand -hex 32
```

Generate a strong secret with:

```bash
openssl rand -hex 32
```

### Access token revocation & Statelessness

JWT access tokens are **stateless** — once issued, they are cryptographically validated without querying the database until their expiration time (`tokenExpiresIn`).

Calling `auth.use('jwt').revoke()` invalidates the **refresh token** stored in the database, preventing attackers from generating *new* access tokens, and clears the access and refresh token cookies set by the guard (when `useCookies` / `useCookiesForRefreshToken` are enabled). However, any existing, unexpired access token will remain valid until `tokenExpiresIn` elapses.

> [!TIP]
> Keep `tokenExpiresIn` short (e.g. `15m` or `1h`) to limit the lifetime of issued access tokens, and rely on `generateWithRefreshToken()` to silently rotate tokens.


