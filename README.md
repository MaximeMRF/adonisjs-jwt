<p align="center">
  <img src="https://maximemax.sirv.com/npm_package_maxime_jwt.png" alt="@maximemrf/adonisjs-jwt">
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@maximemrf/adonisjs-jwt"><img src="https://img.shields.io/npm/dm/@maximemrf/adonisjs-jwt.svg?style=flat-square" alt="Download"></a>
  <a href="https://www.npmjs.com/package/@maximemrf/adonisjs-jwt"><img src="https://img.shields.io/npm/v/@maximemrf/adonisjs-jwt.svg?style=flat-square" alt="Version"></a>
  <a href="https://www.npmjs.com/package/@maximemrf/adonisjs-jwt"><img src="https://img.shields.io/npm/last-update/@maximemrf/adonisjs-jwt.svg?style=flat-square" alt="NPM Last Update"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/npm/l/@maximemrf/adonisjs-jwt.svg?style=flat-square" alt="License"></a>
  <a href="https://adonisjs.com/"><img src="https://img.shields.io/badge/AdonisJS-v6-5A45FF.svg?style=flat-square" alt="AdonisV6"></a>
  <a href="https://adonisjs.com/"><img src="https://img.shields.io/badge/AdonisJS-v7-5A45FF.svg?style=flat-square" alt="AdonisV7"></a>
</p>

> AdonisJS package to authenticate users using JWT tokens.

**📖 Documentation: [maximemrf.github.io/adonisjs-jwt](https://maximemrf.github.io/adonisjs-jwt/)**

- Access tokens signed with HMAC, RSA or ECDSA, or verified with JWKS
- Rotating refresh tokens stored in the database
- Bearer header or `HttpOnly` cookies
- Works with the `auth` middleware and Japa's `loginAs`

## Compatibility

| Package version | AdonisJS version | Node.js     |
| --------------- | ---------------- | ----------- |
| `0.7.x`         | AdonisJS v6      | `>= 20.6.0` |
| `>= 0.8.x`      | AdonisJS v7      | `>= 24.0.0` |

Upgrading from 0.9? Read the [1.0 upgrade guide](https://maximemrf.github.io/adonisjs-jwt/upgrading/1.0).

## Installation

```sh
node ace add @adonisjs/auth # if not installed yet
npm i @maximemrf/adonisjs-jwt
node ace configure @maximemrf/adonisjs-jwt
```

## Quick start

Register the guard in `config/auth.ts`:

```ts
import { defineConfig } from '@adonisjs/auth'
import { sessionUserProvider } from '@adonisjs/auth/session'
import { jwtGuard } from '@maximemrf/adonisjs-jwt'

const authConfig = defineConfig({
  default: 'jwt',
  guards: {
    jwt: jwtGuard({
      provider: sessionUserProvider({
        model: () => import('#models/user'),
      }),
    }),
  },
})

export default authConfig
```

Issue a token and protect routes:

```ts
import router from '@adonisjs/core/services/router'
import { middleware } from '#start/kernel'
import User from '#models/user'

router.post('login', async ({ request, auth }) => {
  const { email, password } = request.only(['email', 'password'])
  const user = await User.verifyCredentials(email, password)
  return await auth.use('jwt').generate(user)
})

router.get('me', async ({ auth }) => auth.getUserOrFail()).use(middleware.auth())
```

Then see the [documentation](https://maximemrf.github.io/adonisjs-jwt/) for refresh tokens, cookies, asymmetric keys, JWKS and security.

## Contributing

```sh
npm install
npm test          # lint, tests and coverage
npm run docs:dev  # documentation, on http://localhost:5173/adonisjs-jwt/
```

## License

MIT
