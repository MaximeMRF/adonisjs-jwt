# Testing

The guard supports the `loginAs` method of the Japa [API client](https://docs.adonisjs.com/guides/testing/http-tests), through the auth plugin of `@adonisjs/auth`.

## Setup

Register the auth plugin in `tests/bootstrap.ts`, if your application doesn't do it yet:

```ts
// tests/bootstrap.ts
import { authApiClient } from '@adonisjs/auth/plugins/api_client'
import app from '@adonisjs/core/services/app'

export const plugins: Config['plugins'] = [
  assert(),
  apiClient(),
  pluginAdonisJS(app),
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
