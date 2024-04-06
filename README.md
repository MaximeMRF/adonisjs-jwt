# AdonisJS Jwt Auth
> AdonisJS package to authenticate users using JWT tokens.

## Prerequisites

You have to install the auth package from AdonisJS with the session guard.

```bash
node ace add @adonisjs/auth --guard=session
```

## Setup

This package is available in the npm registry.

```bash
npm i @maximemrf/adonisjs-jwt
```

## Usage

Go to `config/auth.ts` and add the following configuration:

```typescript
import { defineConfig } from '@adonisjs/auth'
import { InferAuthEvents, Authenticators } from '@adonisjs/auth/types'
import { sessionGuard, sessionUserProvider } from '@adonisjs/auth/session'
import { jwtGuard } from '@maximemrf/adonisjs-jwt/jwt_config'

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
      tokenExpiresIn: '1h',
      provider: sessionUserProvider({
        model: () => import('#models/user'),
      }),
    }),
  },
})
```

## Usage

To make a protected route, you have to use the `auth` middleware with the `jwt` guard.

```typescript
// if the jwt guard is the default guard
router.get('/', async ({ auth }) => {
  return auth.getUserOrFail()
})
.use(middleware.auth())

// if the jwt guard is not the default guard
router.get('/', async ({ auth }) => {
  return auth.use('jwt').getUserOrFail()
})
.use(middleware.auth({ guards: ['jwt'] }))
```
