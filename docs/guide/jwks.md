# JWKS

In JWKS mode, the guard doesn't issue tokens: it verifies tokens signed by an external identity provider (Auth0, Keycloak, Cognito, Kubernetes…), using the public keys the provider publishes as a [JSON Web Key Set](https://datatracker.ietf.org/doc/html/rfc7517).

## Configure the guard

```ts
jwtGuard({
  provider: new MyUserProvider(),
  jwks: {
    jwksUri: 'https://your-auth-server/.well-known/jwks.json',
  },
  issuer: 'https://your-auth-server/',
  audience: 'my-api',
  // the user id is usually in `sub`
  getUserId: (payload) => payload.sub,
})
```

`issuer` and `audience` are **required**: the guard throws at startup if one of them is missing. Without them, any token signed by the provider would be accepted, including tokens issued for other applications. For providers whose tokens have no usable `aud` claim, replace `audience` with [`verifyPayload`](#check-other-claims).

Find the right values in the provider's discovery document, usually at `https://your-auth-server/.well-known/openid-configuration`: `issuer` is given there, and `jwks_uri` is the `jwksUri`. The audience is the identifier of your API registered in the provider.

::: warning Generic audiences
Some providers put the same generic audience in every token of a realm, for example `account` in [FerrisKey](/guide/ferriskey#add-an-audience) and Keycloak. Don't use it as `audience`: your API would accept tokens issued for any other client of the realm. Add an audience mapper instead, so tokens carry an audience specific to your API. The [FerrisKey guide](/guide/ferriskey) shows how, and Keycloak should work the same way with its own audience mapper. You can also check `azp` with [`verifyPayload`](#check-other-claims).
:::

## Check other claims

`verifyPayload` runs on the verified payload, before the user is looked up. Return `false` to reject the token. It can be async.

Use it to check claims that `issuer` and `audience` don't cover, for example a scope or a tenant:

```ts
jwtGuard({
  // ...
  verifyPayload: (payload) => payload.scope?.split(' ').includes('jobs:read'),
})
```

In JWKS mode, `verifyPayload` can replace `audience`, for providers whose access tokens don't carry an audience specific to your API:

- **Amazon Cognito** access tokens have no `aud` claim. They carry the app client in `client_id`, and `token_use: 'access'`, which tells them apart from ID tokens:

  ```ts
  jwtGuard({
    provider: new MyUserProvider(),
    jwks: {
      jwksUri: 'https://cognito-idp.<region>.amazonaws.com/<user-pool-id>/.well-known/jwks.json',
    },
    issuer: 'https://cognito-idp.<region>.amazonaws.com/<user-pool-id>',
    verifyPayload: (payload) =>
      payload.token_use === 'access' && payload.client_id === '<app-client-id>',
    getUserId: (payload) => payload.sub,
  })
  ```

- **FerrisKey** and **Keycloak**, without an audience mapper: check the client that requested the token, in `azp`:

  ```ts
  verifyPayload: (payload) => payload.azp === 'my-api',
  ```

  An audience mapper is still the cleaner option, see the [FerrisKey guide](/guide/ferriskey#add-an-audience).

`verifyPayload` must check that the token was issued for your API: returning `true` for every token reopens the hole `audience` closes.

## User id

Tokens issued by an external provider don't carry a `userId` claim. `getUserId` tells the guard where to find the user id in the verified payload. It defaults to `(payload) => payload.userId`.

The guard then calls `provider.findById()` with this id. If your users are not stored by provider id, write a [custom user provider](/reference/guard#user-provider) that maps the id to your user.

## Algorithms

`algorithms` restricts the accepted signing algorithms. By default, every asymmetric algorithm supported in JWKS mode is accepted: `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384` and `ES512`. Symmetric `HS*` algorithms are never accepted.

```ts
jwtGuard({
  // ...
  algorithms: ['RS256'],
})
```

## Key fetching

The guard uses [`jwks-rsa`](https://github.com/auth0/node-jwks-rsa) to fetch the keys. The `jwks` option accepts every option of `jwks-rsa`. A token with an unknown `kid` triggers a fetch, so the guard applies these defaults, which you can override:

| Option                  | Default |
| ----------------------- | ------- |
| `cache`                 | `true`  |
| `rateLimit`             | `true`  |
| `jwksRequestsPerMinute` | `10`    |
| `timeout`               | `5000`  |

## Clock skew

If the clocks of your server and of the provider drift, set `clockTolerance`, in seconds, to accept tokens that expired a few seconds ago:

```ts
jwtGuard({
  // ...
  clockTolerance: 30,
})
```

It works in every mode, not only JWKS.

## Limitations

- `generate()` and `generateWithRefreshToken()` throw: tokens are issued by the provider.
- Use `authenticate()`, `check()` or the `auth` middleware to verify tokens.
- JWKS can't be combined with asymmetric keys, and `secret` is ignored.

For complete examples, see [FerrisKey](/guide/ferriskey) and [Kubernetes ServiceAccount tokens](/guide/kubernetes).
