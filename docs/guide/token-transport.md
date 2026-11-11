# Cookies and token transport

The access token and the refresh token can travel in the `Authorization` header, in cookies, or in the request body for the refresh token.

## Which transport to pick

- **Browsers**: use cookies. They are `HttpOnly`, so JavaScript can't read them and an XSS can't steal the tokens.
- **Mobile apps, CLIs, other services**: send the access token in the `Authorization` header, and the refresh token in the request body or the `Authorization` header.

## Access token

By default, the guard reads the access token from the `Authorization: Bearer <token>` header. Set `useCookies` to also accept it from a cookie:

```ts
jwtGuard({
  // ...
  useCookies: true,
  tokenName: 'token', // name of the cookie, 'token' by default
})
```

With `useCookies`, `generate()` sets the access token cookie on the response, with a `Max-Age` matching `tokenExpiresIn`.

The guard reads the access token from, in order:

1. the `Authorization: Bearer <token>` header;
2. the cookie named after `tokenName`, only when `useCookies` is enabled.

The header comes first because the client sets it explicitly, while the browser sends cookies on every request: a stale cookie never shadows a valid bearer token.

## Refresh token

Set `useCookiesForRefreshToken` to send the refresh token as a cookie:

```ts
jwtGuard({
  // ...
  useCookiesForRefreshToken: true,
  refreshTokenName: 'refreshToken', // name of the cookie and of the body field
})
```

The guard reads the refresh token from, in order:

1. the cookie named after `refreshTokenName`, when `useCookiesForRefreshToken` is enabled;
2. the request body field named after `refreshTokenName`. This is how OAuth 2.0 transmits refresh tokens ([RFC 6749 §6](https://datatracker.ietf.org/doc/html/rfc6749#section-6));
3. the `Authorization: Bearer <token>` header.

A refresh token passed in the query string is ignored, since URLs end up in access logs, browser history and `Referer` headers.

`useCookies` and `useCookiesForRefreshToken` are independent: you can, for example, keep the access token in memory and send it in the header, while the refresh token lives in a cookie.

## Cookie options

Cookies set by the guard are `HttpOnly` and `Secure` by default. Override these defaults or set other options with `cookie`:

```ts
jwtGuard({
  // ...
  cookie: {
    httpOnly: true, // default
    secure: true, // default
    sameSite: 'strict',
    path: '/',
  },
})
```

`maxAge` and `expires` can't be set: the guard derives them from `tokenExpiresIn` and `refreshTokenExpiresIn`. The same options apply to both cookies.

::: tip CSRF
Browsers send cookies automatically, including on requests triggered by other sites. Use `sameSite: 'strict'` or `'lax'`, or enable the [CSRF protection](https://docs.adonisjs.com/guides/security/securing-ssr-applications#csrf-protection) of AdonisJS, when you authenticate with cookies.
:::

## Logging

Make sure your logging middleware doesn't record request bodies, cookies or `Authorization` headers on authentication routes, otherwise tokens end up in plain text in your logs.
