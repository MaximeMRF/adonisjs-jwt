# Guard API

Methods and properties of the guard returned by `auth.use('jwt')`.

## Methods

### generate(user)

Issues an access token for the user, and a refresh token when refresh tokens are configured. Sets the cookies when `useCookies` / `useCookiesForRefreshToken` are enabled.

```ts
const result = await auth.use('jwt').generate(user)
```

Returns a `JwtGenerateResult`:

```ts
type JwtGenerateResult = {
  type: string // 'bearer'
  token: string
  expiresIn?: number | string // tokenExpiresIn
  refreshToken?: string
  refreshTokenExpiresIn?: number | string
}
```

When the guard has a `refreshTokenUserProvider`, `refreshToken` is typed as `string`, so no non-null assertion is needed.

Throws in JWKS mode.

### authenticate()

Reads the access token from the request, verifies it and loads the user. Returns the user, with `currentToken` set to the access token. Throws `E_UNAUTHORIZED_ACCESS` if the request is not authenticated.

The `auth` middleware calls it for you. Calling it several times in the same request only authenticates once.

### check()

Same as `authenticate()`, but returns `true` or `false` instead of throwing.

### getUserOrFail()

Returns the authenticated user, or throws `E_UNAUTHORIZED_ACCESS`.

### generateWithRefreshToken(refreshToken?)

Exchanges a refresh token for a new access token and a new refresh token, and deletes the used refresh token. Reads the refresh token from the request when it isn't passed. Returns a `JwtGenerateResult`, and authenticates the user, with `currentToken` set to the new access token.

Throws `E_UNAUTHORIZED_ACCESS` if the refresh token is missing, unknown, expired, already used or lacks the `refreshTokenAbilities`. See [Refresh tokens](/guide/refresh-tokens).

### revoke(refreshToken?)

Deletes the refresh token from the database and clears the cookies set by the guard. Reads the refresh token from the request when it isn't passed. Throws if refresh tokens are not configured.

### authenticateAsClient(user)

Used by Japa's `loginAs`. See [Testing](/guide/testing).

## Properties

| Property                  | Description                                                 |
| ------------------------- | ----------------------------------------------------------- |
| `user`                    | The authenticated user, with `currentToken`, or `undefined` |
| `isAuthenticated`         | `true` once the request is authenticated                    |
| `authenticationAttempted` | `true` once an authentication has been attempted            |
| `driverName`              | `'jwt'`                                                     |

## User provider

The `provider` option accepts any object implementing `JwtUserProviderContract`. `sessionUserProvider()` from `@adonisjs/auth/session` implements it for Lucid models. To authenticate something else, for example services identified by an external token, write your own:

```ts
import { symbols } from '@adonisjs/auth'
import type { JwtGuardUser, JwtUserProviderContract } from '@maximemrf/adonisjs-jwt/types'

type Service = { id: string; name: string }

export class ServiceUserProvider implements JwtUserProviderContract<Service> {
  declare [symbols.PROVIDER_REAL_USER]: Service

  async createUserForGuard(service: Service): Promise<JwtGuardUser<Service>> {
    return {
      getId: () => service.id,
      getOriginal: () => service,
    }
  }

  async findById(id: string | number | BigInt): Promise<JwtGuardUser<Service> | null> {
    const service = await findServiceSomehow(String(id))
    return service ? this.createUserForGuard(service) : null
  }
}
```

- `findById` receives the id returned by `getUserId` (by default the `userId` claim). Return `null` to reject the token.
- `createUserForGuard` wraps the user passed to `generate()`.

## Exports

```ts
// main entrypoint
import { jwtGuard, JwtGuard, DEFAULT_TOKEN_EXPIRES_IN } from '@maximemrf/adonisjs-jwt'

// types
import type {
  JwtGuardOptions,
  JwtGuardUser,
  JwtUserProviderContract,
  JwtGenerateResult,
  BaseJwtContent,
  JwtCookieOptions,
} from '@maximemrf/adonisjs-jwt/types'
```

`@maximemrf/adonisjs-jwt/jwt_config` still exports `jwtGuard`, for compatibility with 0.x.
