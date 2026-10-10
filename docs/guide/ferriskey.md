# FerrisKey

[FerrisKey](https://ferriskey.rs) is an open-source identity and access management server, with realms, clients, users, roles and standard OpenID Connect flows. Your AdonisJS API can verify the tokens it issues in [JWKS](/guide/jwks) mode, without sharing any secret.

This guide was tested end to end against FerrisKey v0.9.0, with tokens issued by the `client_credentials` grant.

## Find the endpoints

Each realm publishes its discovery document at `https://<ferriskey-host>/api/realms/<realm>/.well-known/openid-configuration`. The two values the guard needs are:

| Discovery field | Example                                                                     | Guard option    |
| --------------- | --------------------------------------------------------------------------- | --------------- |
| `issuer`        | `https://auth.example.com/api/realms/my-realm`                              | `issuer`        |
| `jwks_uri`      | `https://auth.example.com/api/realms/my-realm/protocol/openid-connect/jwks.json` | `jwks.jwksUri` |

FerrisKey signs tokens with `RS256`.

## Create a client

In the FerrisKey console, open your realm and create a client:

- **Client ID**: the identifier of your API, for example `my-api`;
- **Client authentication**: **Confidential**, required for the `client_credentials` grant. It can't be changed afterwards;
- **Direct access grants** and **Device authorization grant**: disabled, unless you need them.

Then enable the **service account** of the client, and copy the **client secret** from its **Credentials** tab. The service account is the user the `client_credentials` tokens are issued for.

## Add an audience

By default, FerrisKey puts generic values in the `aud` claim, for example `["my-realm", "account"]`, and the client that requested the token in `azp`. Every token of the realm carries these values: with `audience: 'account'`, your API would accept tokens issued for any other client of the realm.

Add an audience mapper so tokens carry an audience specific to your API:

1. In **Client Scopes**, create a client scope in the realm of your client, for example `my-api-audience`.
2. In its **Protocol Mappers** tab, add a mapper of type **Audience** (`oidc-audience-mapper`):
   - **Client audience**: `my-api`, or leave it empty and set a **Custom audience**;
   - **Add to access token**: enabled.
3. In **Clients**, open your client, and in its **Client Scopes** tab, assign the scope as **default**, so it's included without being requested. The scope itself can stay optional at the realm level: the assignment to the client decides.
4. Check the result in the **Evaluate** tab of the client, or request a new token.

New tokens now contain your audience:

```json
{
  "iss": "https://auth.example.com/api/realms/my-realm",
  "aud": ["my-realm", "account", "my-api"],
  "azp": "my-api",
  "sub": "01a126dd-bb20-70c2-b722-2a64312f84f2",
  "scope": "openid my-api-audience email profile roles"
}
```

::: tip
Make sure you're in the right realm in the console: a client scope created in `master` is not available to the clients of another realm.
:::

Without an audience mapper, you can instead check the client that requested the token, in `azp`, with [`verifyPayload`](/guide/jwks#check-other-claims) in place of `audience`. This was tested against FerrisKey too, but the audience mapper is the standard way.

## Configure the guard

```ts
// config/auth.ts
import { defineConfig } from '@adonisjs/auth'
import { jwtGuard } from '@maximemrf/adonisjs-jwt'
import { FerrisKeyUserProvider } from '../app/auth/ferriskey_user_provider.js'

const FERRISKEY_REALM = 'https://auth.example.com/api/realms/my-realm'

const authConfig = defineConfig({
  default: 'jwt',
  guards: {
    jwt: jwtGuard({
      provider: new FerrisKeyUserProvider(),
      jwks: {
        jwksUri: `${FERRISKEY_REALM}/protocol/openid-connect/jwks.json`,
      },
      issuer: FERRISKEY_REALM,
      audience: 'my-api',
      algorithms: ['RS256'],
      getUserId: (payload) => payload.sub,
    }),
  },
})

export default authConfig
```

`FerrisKeyUserProvider` is your own [user provider](/reference/guard#user-provider). Its `findById` receives the `sub` claim, the id of the FerrisKey user or service account. When the users only live in FerrisKey, it can accept every verified token:

```ts
// app/auth/ferriskey_user_provider.ts
import { symbols } from '@adonisjs/auth'
import type { JwtGuardUser, JwtUserProviderContract } from '@maximemrf/adonisjs-jwt/types'

export type FerrisKeyUser = { id: string }

export class FerrisKeyUserProvider implements JwtUserProviderContract<FerrisKeyUser> {
  declare [symbols.PROVIDER_REAL_USER]: FerrisKeyUser

  async createUserForGuard(user: FerrisKeyUser): Promise<JwtGuardUser<FerrisKeyUser>> {
    return { getId: () => user.id, getOriginal: () => user }
  }

  async findById(id: string | number | BigInt): Promise<JwtGuardUser<FerrisKeyUser> | null> {
    return this.createUserForGuard({ id: String(id) })
  }
}
```

To attach your own data to FerrisKey users, store the FerrisKey id in a column of your model and look the user up by this column in `findById`, returning `null` for unknown ids.

## Call the API

Request a token with the `client_credentials` grant, then send it as a bearer token:

```sh
TOKEN=$(curl -s -X POST \
  https://auth.example.com/api/realms/my-realm/protocol/openid-connect/token \
  -d grant_type=client_credentials \
  -d client_id=my-api \
  -d client_secret=<client-secret> | jq -r .access_token)

curl http://localhost:3333/me -H "Authorization: Bearer $TOKEN"
```

```ts
router
  .get('me', async ({ auth }) => {
    return { id: auth.getUserOrFail().id }
  })
  .use(middleware.auth({ guards: ['jwt'] }))
```

Tokens issued to users, for example by a frontend using the authorization code flow, are verified the same way, as long as they carry your audience.

## Token lifetime and revocation

FerrisKey access tokens expire after 5 minutes by default (`access_token_lifetime_secs` on the realm, overridable per client). Clients request a new token when it expires, the guard never issues FerrisKey tokens itself.

Tokens are verified offline against the JWKS: a token stays valid until its `exp`, even if the user or the client is disabled in FerrisKey in the meantime. Keep the lifetime short. If you need immediate revocation, call the FerrisKey introspection endpoint (`/protocol/openid-connect/token/introspect`) from your user provider.
