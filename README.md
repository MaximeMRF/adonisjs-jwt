# AdonisJS Jwt Auth
> AdonisJS package to authenticate users using JWT tokens.

## Prerequisites

You have to install the auth package from AdonisJS with the session guard because the jwt package use some components from the session guard.

```bash
node ace add @adonisjs/auth --guard=session
```

## Setup

Install the package:

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
import { JwtGuardUser } from '@maximemrf/adonisjs-jwt/types'
import User from '#models/user'

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
      // tokenExpiresIn can be a string or a number, it can be optional
      tokenExpiresIn: '1h',
      // if you want to use cookies for the authentication instead of the bearer token (optional)
      useCookies: true,
      provider: sessionUserProvider({
        model: () => import('#models/user'),
      }),
      // content is a function that takes the user and returns the content of the token, it can be optional, by default it returns only the user id
      content: (user: JwtGuardUser<User>) => ({
        id: user.getId(),
        email: user.getOriginal().email,
      }),
    }),
  },
})
```

`tokenExpiresIn` is the time before the token expires it can be a string or a number and it can be optional.

```typescript
// string
tokenExpiresIn: '1h'
// number
tokenExpiresIn: 60 * 60
```

You can also use cookies for the authentication instead of the bearer token by setting `useCookies` to `true`.

```typescript
useCookies: true
```

If you just want to use jwt with the bearer token no need to set `useCookies` to `false` you can just remove it.

## Usage

To make a protected route, you have to use the `auth` middleware with the `jwt` guard.

```typescript
router.post('login', async ({ request, auth }) => {
  const { email, password } = request.all()
  const user = await User.verifyCredentials(email, password)

  // to generate a token
  return await auth.use('jwt').generate(user)
})

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

## Security

We use natively the AdonisJS application key to sign the token, so you don't have to worry about it and [avoid this](https://trufflesecurity.com/blog/stop-recommending-jwts).
