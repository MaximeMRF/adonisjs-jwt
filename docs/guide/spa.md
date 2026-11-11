# Single-page apps

A single-page app (React, Vue, Svelte…) served from another origin than the API can keep the tokens in memory and send them in the `Authorization` header, or let the browser store them in `HttpOnly` cookies. This page covers what the browser adds on top of [Cookies and token transport](/guide/token-transport).

## Where to store the tokens

| Storage | Survives a reload | Readable by an XSS |
| ------- | ----------------- | ------------------ |
| Memory, `Authorization` header | No: call `/refresh` when the app starts, with a refresh token kept elsewhere | Yes, while the page is open |
| `localStorage` | Yes | Yes. Avoid it for the refresh token |
| `HttpOnly` cookies | Yes | No, see below |
| Access token in memory, refresh token in a cookie | Yes | The access token only |

`HttpOnly` cookies keep the tokens out of reach of JavaScript, but an XSS can still send requests with them, and read the responses of your routes. So in cookie mode, don't return the tokens in the response body.

## Cookie mode

```ts
// config/auth.ts
jwt: jwtGuard({
  // ...
  useCookies: true,
  useCookiesForRefreshToken: true,
  cookie: {
    sameSite: 'lax',
    secure: app.inProduction,
  },
})
```

`generate()` and `generateWithRefreshToken()` set the cookies and also return the tokens. Return only what the app needs:

```ts
router.post('login', async ({ request, auth }) => {
  const { email, password } = request.only(['email', 'password'])
  const user = await User.verifyCredentials(email, password)
  const { expiresIn } = await auth.use('jwt').generate(user)
  return { expiresIn } // not the tokens: they are in the cookies
})

router.post('refresh', async ({ auth }) => {
  const { expiresIn } = await auth.use('jwt').generateWithRefreshToken()
  return { expiresIn }
})
```

The client sends the cookies with `credentials: 'include'` (`withCredentials: true` with axios), on every request, including `/refresh` and `/logout`.

### SameSite and two domains

Browsers only send `SameSite=Lax` or `Strict` cookies when the app and the API are on the **same site**: `app.example.com` and `api.example.com` are, `my-app.vercel.app` and `my-api.fly.dev` are not, and neither are `localhost` and `127.0.0.1`. Between two sites, the login succeeds but the browser silently drops the cookies, and the next request gets a `401`.

Prefer serving the app and the API under the same domain (subdomains, or a reverse proxy, or the Vite dev server proxy in development). `sameSite: 'none'` makes cookies work between two sites, but exposes the routes to cross-site requests (see [CSRF](/guide/token-transport#csrf)) and is blocked by browsers that block third-party cookies.

### Secure cookies in development

Cookies are `Secure` by default. Chromium and Firefox accept them on `http://localhost`, other browsers and other hostnames (a LAN IP for a phone) may not. Use `secure: app.inProduction`.

## CORS

Allow the origin of the app explicitly, with credentials, in `config/cors.ts`:

```ts
const corsConfig = defineConfig({
  enabled: true,
  origin: ['https://app.example.com'],
  credentials: true,
  // ...
})
```

Don't use `origin: true` or `'*'` with `credentials`: `@adonisjs/cors` then allows the origin of every request, so any site could send authenticated requests to the API and read the responses, within the limits of `SameSite`.

## Handle 401 responses

The guard answers `401` with `{ "errors": [{ "message": "Unauthorized access" }] }` when the request asks for JSON. `fetch()` sends `Accept: */*` by default, which gets a plain text body in apps that don't force JSON responses (the AdonisJS API starter kit does). Set the header in your fetch wrapper.

A refresh token can only be used once: when several requests fail at the same time with an expired access token, refresh **once** and retry them all.

```ts
let refreshing: Promise<boolean> | undefined

async function api(path: string, init: RequestInit = {}) {
  const request = () =>
    fetch(`${API_URL}${path}`, {
      ...init,
      credentials: 'include',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json', ...init.headers },
    })

  let response = await request()
  if (response.status !== 401 || path === '/refresh') return response

  refreshing ??= fetch(`${API_URL}/refresh`, {
    method: 'POST',
    credentials: 'include',
    headers: { Accept: 'application/json' },
  })
    .then((res) => res.ok)
    .finally(() => (refreshing = undefined))

  if (await refreshing) response = await request()
  return response
}
```

Two tabs can still refresh at the same time: the one that loses gets a `401` but keeps the cookies set by the other one, so its next request succeeds. Retry once more before showing the login page, or coordinate tabs with the [Web Locks API](https://developer.mozilla.org/docs/Web/API/Web_Locks_API).

## Log out

The client must send the **refresh token** to revoke it. In cookie mode, the browser sends it:

```ts
await api('/logout', { method: 'POST' })
```

In header mode, send it in the body. The access token alone is not enough: the request fails with a `401` and the refresh token stays valid.

```ts
await fetch(`${API_URL}/logout`, {
  method: 'POST',
  headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
  body: JSON.stringify({ refreshToken }),
})
```

A `401` on logout means that nothing was revoked, because the refresh token had already expired or been revoked. The app can forget the tokens either way. See [Revoke a refresh token](/guide/refresh-tokens#revoke-a-refresh-token).
