---
description: "Test AdonisJS routes protected by the JWT guard with Japa: loginAs with the API client, and the session guard alongside."
---

# Testing

The guard supports the `loginAs` method of the Japa [API client](https://docs.adonisjs.com/guides/testing/http-tests), through the auth plugin of `@adonisjs/auth`.

## Setup

`loginAs` needs the Japa API client. The API starter kit already has it. The Inertia and web starter kits only ship the browser client, so install it first:

```sh
npm i -D @japa/api-client
```

Then register the API client and the auth plugin in `tests/bootstrap.ts`, if your application doesn't do it yet:

```ts
// tests/bootstrap.ts
import { apiClient } from '@japa/api-client'
import { authApiClient } from '@adonisjs/auth/plugins/api_client'
import app from '@adonisjs/core/services/app'

export const plugins: Config['plugins'] = [
  assert(),
  apiClient(),
  pluginAdonisJS(app),
  authApiClient(app),
]
```

If the app also keeps the session guard (the Inertia and web starter kits), register the session plugin too, otherwise `loginAs` on the session guard fails with `request.withSession is not a function`:

```ts
import { sessionApiClient } from '@adonisjs/session/plugins/api_client'

export const plugins: Config['plugins'] = [
  assert(),
  apiClient(),
  pluginAdonisJS(app),
  sessionApiClient(app),
  authApiClient(app),
]
```

## Log in as a user

```ts
import { test } from '@japa/runner'
import User from '#models/user'

test('returns the current user', async ({ client }) => {
  const user = await User.create({ email: 'jane@example.com', password: 'secret' })

  const response = await client.get('/me').loginAs(user)

  response.assertStatus(200)
})
```

`loginAs` issues an access token for the user and sends it in the `Authorization` header. To use the JWT guard when it isn't the default one, name it: `.withGuard('jwt').loginAs(user)`.

::: info Browser tests
The browser client of `@adonisjs/auth` (`browserContext.loginAs`) isn't supported: it expects cookies, and the guard returns a header. In browser tests, log in through your login form.
:::
