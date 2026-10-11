# Asymmetric signing

With asymmetric signing, the guard signs access tokens with a **private key** and verifies them with the matching **public key**. Other services can verify your tokens with the public key alone, without being able to issue tokens.

Supported algorithms: `RS256`, `RS384`, `RS512` (RSA) and `ES256`, `ES384`, `ES512` (ECDSA).

## Generate a key pair

```sh
# RSA
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem

# ECDSA (P-256, for ES256)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem
```

Never commit the private key. Store it in an environment variable or a secret manager.

## Configure the guard

Set `privateKey`, `publicKey` and `algorithm` together:

```ts
import env from '#start/env'

jwtGuard({
  provider: sessionUserProvider({
    model: () => import('#models/user'),
  }),
  privateKey: env.get('JWT_PRIVATE_KEY').replace(/\\n/g, '\n'),
  publicKey: env.get('JWT_PUBLIC_KEY').replace(/\\n/g, '\n'),
  algorithm: 'RS256',
})
```

The `.replace()` restores the line breaks of PEM keys stored on a single line in `.env`.

The guard checks at startup that the keys are valid and match the algorithm. It throws if only some of the three options are set.

Notes:

- `secret` is ignored when the keys are set.
- Asymmetric signing can't be combined with `jwks`.
- Only tokens signed with the configured algorithm are accepted, so a token signed with HMAC using the public key as secret is rejected.

## Verify tokens in another service

Other services verify the tokens with the public key, with any JWT library. For example, with `jsonwebtoken`:

```ts
import jwt from 'jsonwebtoken'

const payload = jwt.verify(token, publicKey, {
  algorithms: ['RS256'],
  issuer: 'my-app',
  audience: 'my-api',
})
```

Always pin `algorithms`. If the other service is an AdonisJS application, you can also expose the public key as a JWKS and use the [JWKS mode](/guide/jwks).
