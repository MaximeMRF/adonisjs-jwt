# Cookies and token transport

The access token and the refresh token can travel in the `Authorization` header, in cookies, or in the request body for the refresh token.

## Which transport to pick

- **Browsers**: use cookies. They are `HttpOnly`, so JavaScript can't read them. Don't return the tokens in the response body as well, see [Single-page apps](/guide/spa#cookie-mode).
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

Options that you don't set come from `http.cookie` in `config/app.ts` (`sameSite: 'lax'` and `path: '/'` in new apps). The cookies are signed with the application key, not encrypted: they can't be forged, and they are `HttpOnly`, but the JWT inside is readable by anyone who gets the cookie, like any JWT.

Use `secure: app.inProduction` if you develop over plain HTTP on another hostname than `localhost`.

## CSRF

Browsers send cookies automatically, including on requests triggered by other sites. When you authenticate with cookies, protect the routes that change data:

- **`sameSite: 'lax'` or `'strict'`** stops other sites from sending the cookies with their `POST` requests. `lax` still sends them on top-level `GET` navigations, so `GET` routes must not change data. `SameSite` works per site, not per origin: another subdomain of your domain, for example one that hosts user content, is the same site.
- **The [CSRF protection](https://docs.adonisjs.com/guides/security/securing-ssr-applications#csrf-protection) of `@adonisjs/shield`** (with `@adonisjs/session`) adds a token check. Inertia forms send the token automatically. A SPA reads the `XSRF-TOKEN` cookie and sends it back in the `X-XSRF-TOKEN` header (axios does it by default, see [Single-page apps](/guide/spa#with-the-csrf-protection-of-shield) for `fetch()`). By default, Shield answers an invalid token with a redirect back, not a `403`: handle `E_BAD_CSRF_TOKEN` in your exception handler if your API clients need a status code.

The CSRF protection applies to every `POST` route, including those used by mobile apps or other services that send the token in the `Authorization` header and have no CSRF token. Exclude them with `exceptRoutes`, and authenticate them with a second JWT guard without cookies, so that a cookie can't authenticate a request on a route that Shield no longer protects.

## Logging

Make sure your logging middleware doesn't record request bodies, cookies or `Authorization` headers on authentication routes, otherwise tokens end up in plain text in your logs.
