# Security

## Signing key

When no `secret` is configured, the guard signs tokens with a key derived from the AdonisJS application key, with HKDF-SHA256 salted with the guard name. You don't have to manage a separate secret, and:

- the raw application key is never used to sign JWTs, so values signed elsewhere with the application key (signed URLs, cookies…) are not accepted as access tokens;
- two JWT guards never accept each other's tokens.

The application key is read from `appKey` in `config/app.ts` when it exists (apps created with AdonisJS v6), otherwise from the `APP_KEY` environment variable. It must be at least 32 characters, otherwise the guard throws at startup.

Rotating the application key invalidates every access token. Refresh tokens are stored in the database and stay valid, so clients can get a new access token without logging in again.

## Secret strength

With a custom `secret`, it must be at least 32 characters long, otherwise the guard throws at startup. A short secret can be brute-forced offline once an attacker gets hold of a single signed token. Generate one with:

```sh
openssl rand -hex 32
```

## Token verification

The guard rejects:

- expired tokens, and tokens not valid yet (`nbf`), with an optional [`clockTolerance`](/reference/options#clocktolerance);
- tokens signed with another algorithm than the configured one, including unsigned tokens (`alg: none`) and HMAC tokens signed with a public key;
- tokens whose `iss` or `aud` don't match `issuer` and `audience`, when set;
- tokens whose user can't be found by the provider.

Errors are not detailed in the response: every failure is an `E_UNAUTHORIZED_ACCESS` error.

## Access tokens are stateless

Once issued, an access token is valid until it expires: the guard verifies its signature, without looking it up in a token store. Revoking the refresh token or logging out doesn't invalidate the access tokens already issued.

The guard does load the user with the provider's `findById` on each request, so a deleted user is rejected. To lock out a user who still exists, for example a banned account, return `null` from `findById` for this user.

Keep `tokenExpiresIn` short, e.g. `15m`, and use [refresh tokens](/guide/refresh-tokens) to keep users logged in.

## Refresh tokens

- Refresh tokens are stored hashed in the database.
- Each refresh token can be used once. A replayed refresh token is rejected, and only one of two concurrent refreshes with the same token succeeds.
- Set `refreshTokenExpiresIn`, otherwise refresh tokens never expire.
- Refresh tokens are never read from the query string.

## Cookies

- Cookies are `HttpOnly` and `Secure` by default.
- When you authenticate with cookies, protect your application against CSRF with `sameSite` or the CSRF protection of AdonisJS. See [Cookies and token transport](/guide/token-transport#cookie-options).

## Logs

Make sure your logging middleware doesn't record request bodies, cookies or `Authorization` headers on authentication routes, otherwise tokens end up in plain text in your logs.

