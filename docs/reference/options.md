# Options

Options of `jwtGuard()`, in `config/auth.ts`.

```ts
import { jwtGuard } from '@maximemrf/adonisjs-jwt'
```

## User

### provider

**Required.** Finds users by id when verifying a token, and wraps the user passed to `generate()`. `sessionUserProvider` from `@adonisjs/auth/session` works with any Lucid model. See [user provider](/reference/guard#user-provider) to write your own.

### content

`(user) => Record<string, any> & { userId }`. Returns the payload of the access tokens. `user.getOriginal()` is typed after the provider's model.

Default: `(user) => ({ userId: user.getId() })`.

Don't set `exp`, use `tokenExpiresIn`.

### getUserId

`(payload) => string | number | BigInt | undefined | null`. Extracts the user id from a verified payload, before calling `provider.findById()`.

Default: `(payload) => payload.userId`. Use `(payload) => payload.sub` for tokens issued by an external provider.

### verifyPayload

`(payload) => boolean | Promise<boolean>`. Extra check on a verified payload, run before `getUserId`. Return `false` to reject the token.

Default: none. In JWKS mode, it can replace `audience`, see [Check other claims](/guide/jwks#check-other-claims).

## Access tokens

### tokenExpiresIn

`number | string`. Lifetime of access tokens, in seconds or as a duration string (`'15m'`, `'1h'`, `'7d'`).

Default: `'1h'`. A number must be positive.

### issuer

`string`. Added as the `iss` claim to signed tokens, and required on incoming tokens. **Required** in JWKS mode.

### audience

`string | string[]`. Added as the `aud` claim to signed tokens, and required on incoming tokens. **Required** in JWKS mode, unless `verifyPayload` is set.

### clockTolerance

`number`. Seconds of clock skew tolerated when checking `exp` and `nbf`. Works in every mode.

## Signing

Pick one of: a symmetric secret (default), an asymmetric key pair, or JWKS.

### secret

`string`. HMAC secret, at least 32 characters.

Default: a key derived from the application key, see [Security](/guide/security#signing-key).

### privateKey, publicKey, algorithm

PEM-encoded private and public keys, and the signing algorithm: `'RS256'`, `'RS384'`, `'RS512'`, `'ES256'`, `'ES384'` or `'ES512'`. Must be set together. See [Asymmetric signing](/guide/asymmetric).

### jwks

`jwks-rsa` options, at least `jwksUri`. Verifies tokens issued by an external provider, see [JWKS](/guide/jwks).

Defaults: `cache: true`, `rateLimit: true`, `jwksRequestsPerMinute: 10`, `timeout: 5000`.

### algorithms

Algorithms accepted in JWKS mode, a non-empty subset of `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384` and `ES512`.

Default: all of them.

## Refresh tokens

### refreshTokenUserProvider

A `tokensUserProvider()` from `@adonisjs/auth/access_tokens`. Enables refresh tokens, see [Refresh tokens](/guide/refresh-tokens).

### refreshTokenExpiresIn

`number | string`. Lifetime of refresh tokens.

Default: none, refresh tokens never expire.

### refreshTokenAbilities

`string[]`. Abilities given to new refresh tokens. When set, `generateWithRefreshToken()` rejects refresh tokens that don't have all of them.

## Cookies

### useCookies

`boolean`. Sets the access token cookie in `generate()`, and accepts the access token from this cookie.

Default: `false`.

### tokenName

`string`. Name of the access token cookie.

Default: `'token'`.

### useCookiesForRefreshToken

`boolean`. Sets the refresh token cookie in `generate()` and `generateWithRefreshToken()`, and reads the refresh token from this cookie first.

Default: `false`.

### refreshTokenName

`string`. Name of the refresh token cookie and of the request body field the refresh token is read from.

Default: `'refreshToken'`.

### cookie

Cookie options of AdonisJS, except `maxAge` and `expires`, which are derived from the token lifetimes. Applies to both cookies.

Default: `{ httpOnly: true, secure: true }`, merged with your options.
