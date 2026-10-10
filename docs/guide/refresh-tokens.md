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

Without `refreshTokenExpiresIn`, refresh tokens never expire. Setting it is recommended.

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

`refreshTokenAbilities` sets the abilities given to new refresh tokens. When it is set, `generateWithRefreshToken()` rejects refresh tokens that don't have all of them:

```ts
jwtGuard({
  // ...
  refreshTokenAbilities: ['refresh_token'],
})
```

This guards against a misconfiguration where `refreshTokenUserProvider` points to a provider that also stores other tokens. The token `type` remains the main protection.

## Revoke a refresh token

`revoke()` deletes the refresh token of the request from the database and clears the access and refresh token cookies set by the guard:

```ts
router.post('logout', async ({ auth }) => {
  await auth.use('jwt').revoke()
  return { message: 'Logged out' }
})
```

It reads the refresh token like `generateWithRefreshToken()`, or accepts it as argument: `revoke(token)`. If the request carries no refresh token, it only clears the cookies.

::: warning
Revoking a refresh token doesn't invalidate the access tokens already issued: they stay valid until they expire. Keep `tokenExpiresIn` short. See [Security](/guide/security#access-tokens-are-stateless).
:::
