# Refresh tokens

Short-lived access tokens limit the damage of a leaked token, but force users to log in again often. Refresh tokens solve this: the client exchanges a long-lived refresh token for a new access token when the old one expires.

Refresh tokens are opaque tokens stored in the database, using the [access tokens provider](https://docs.adonisjs.com/guides/authentication/access-tokens-guard) of `@adonisjs/auth`. Each refresh token can be used **once**: it is deleted and replaced by a new one on every refresh.

::: info
Refresh tokens are not available in [JWKS](/guide/jwks) mode, where tokens are issued by an external provider.
:::

## Create the table

With refresh tokens, `node ace configure @maximemrf/adonisjs-jwt` does the three steps below for you, see [Installation](/guide/installation). To do them yourself, create the migration:

```ts
// database/migrations/xxxx_create_jwt_refresh_tokens_table.ts
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

::: tip UUID primary keys
If your users have UUID primary keys, replace the `tokenable_id` column with `table.uuid('tokenable_id')` (keep the foreign key).
:::

Then run `node ace migration:run`.

## Configure the model

Add a `refreshTokens` provider to your user model:

```ts
// app/models/user.ts
import { BaseModel, column } from '@adonisjs/lucid/orm'
import { DbAccessTokensProvider } from '@adonisjs/auth/access_tokens'

export default class User extends BaseModel {
  @column({ isPrimary: true })
  declare id: number

  @column()
  declare email: string

  static refreshTokens = DbAccessTokensProvider.forModel(User, {
    prefix: 'rt_',
    table: 'jwt_refresh_tokens',
    type: 'jwt_refresh_token',
    tokenSecretLength: 40,
  })
}
```

The `type` keeps refresh tokens apart from other tokens: a token of another type, like an API access token, is never accepted as a refresh token.

## Configure the guard

Set `refreshTokenUserProvider`, and optionally the lifetime of refresh tokens:

```ts
// config/auth.ts
import { tokensUserProvider } from '@adonisjs/auth/access_tokens'

jwtGuard({
  // ...
  tokenExpiresIn: '15m',
  refreshTokenUserProvider: tokensUserProvider({
    tokens: 'refreshTokens',
    model: () => import('#models/user'),
  }),
  refreshTokenExpiresIn: '7d',
})
```

Without `refreshTokenExpiresIn`, refresh tokens expire after 7 days.

`generate()` now returns a refresh token next to the access token.

## Refresh the access token

Expose a route that calls `generateWithRefreshToken()`. This route must not use the `auth` middleware, since the access token is usually expired when the client calls it:

```ts
router.post('jwt/refresh', async ({ auth }) => {
  return await auth.use('jwt').generateWithRefreshToken()
})
```

`generateWithRefreshToken()`:

1. reads the refresh token from the request (see below);
2. verifies it, and checks that it has not expired;
3. deletes it from the database;
4. returns a new access token and a new refresh token, like `generate()`.

A refresh token that has already been used is rejected. When two requests use the same refresh token at the same time, only one of them succeeds.

The refresh token is read from, in order:

1. the cookie named after `refreshTokenName`, when `useCookiesForRefreshToken` is enabled;
2. the request body field named after `refreshTokenName` (`refreshToken` by default);
3. the `Authorization: Bearer <token>` header.

```http
POST /jwt/refresh HTTP/1.1
Content-Type: application/json

{ "refreshToken": "rt_MQ.xxxxxxxx" }
```

A refresh token in the query string is ignored. You can also pass the token yourself: `generateWithRefreshToken(token)`. See [Cookies and token transport](/guide/token-transport) to choose between these options.

## Refresh token abilities

`refreshTokenAbilities` sets the abilities given to new refresh tokens. When it is set, `generateWithRefreshToken()` and `revoke()` reject refresh tokens that don't have all of them:

```ts
jwtGuard({
  // ...
  refreshTokenAbilities: ['refresh_token'],
})
```

This guards against a misconfiguration where `refreshTokenUserProvider` points to a provider that also stores other tokens. The token `type` remains the main protection.

## Several JWT guards

Access tokens are signed with a key per guard, but refresh tokens are looked up by their tokens provider: two guards that share one accept each other's refresh tokens, to refresh and to log out. Give each guard its own provider, with a distinct `type`. They can share the table, `@adonisjs/auth` filters every query by `type`:

```ts
// app/models/user.ts
static refreshTokens = DbAccessTokensProvider.forModel(User, {
  table: 'jwt_refresh_tokens',
  type: 'jwt_refresh_token',
})

static adminRefreshTokens = DbAccessTokensProvider.forModel(User, {
  table: 'jwt_refresh_tokens',
  type: 'jwt_admin_refresh_token',
})
```

```ts
// config/auth.ts
jwt: jwtGuard({
  // ...
  refreshTokenUserProvider: tokensUserProvider({
    tokens: 'refreshTokens',
    model: () => import('#models/user'),
  }),
}),
jwt_admin: jwtGuard({
  // ...
  refreshTokenUserProvider: tokensUserProvider({
    tokens: 'adminRefreshTokens',
    model: () => import('#models/user'),
  }),
  tokenName: 'adminToken',
  refreshTokenName: 'adminRefreshToken',
}),
```

When both guards use cookies, also give them distinct `tokenName` and `refreshTokenName`, otherwise they write the same cookies. `refreshTokenName` also names the request body field: with the config above, a client sends its refresh token to the `jwt_admin` guard as `{ "adminRefreshToken": "..." }`, or in the `Authorization` header.

## Revoke a refresh token

`revoke()` deletes the refresh token of the request from the database and clears the access and refresh token cookies set by the guard:

```ts
router.post('logout', async ({ auth }) => {
  await auth.use('jwt').revoke()
  return { message: 'Logged out' }
})
```

It accepts the refresh token as argument: `revoke(token)`. Otherwise it revokes the refresh token issued earlier in the same request, if any (for example by a middleware that refreshed an expired access token), or else reads it from the request like `generateWithRefreshToken()`.

The cookies are cleared when the refresh token is revoked, and when no valid refresh token is found (none sent, unknown, already revoked). In that case nothing is revoked and `revoke()` throws `E_UNAUTHORIZED_ACCESS`, so the client gets a `401` instead of believing it has logged out. On any other error, for example when the database is down, the error is thrown and the cookies are kept, so the client can log out again later.

::: warning Bearer clients
A client that keeps its tokens in memory must send its **refresh token** on logout, in the body or the `Authorization` header. If it only sends its access token, the logout fails with a `401` and the refresh token stays valid.
:::

::: warning
Revoking a refresh token doesn't invalidate the access tokens already issued: they stay valid until they expire. Keep `tokenExpiresIn` short. See [Security](/guide/security#access-tokens-are-stateless).
:::
