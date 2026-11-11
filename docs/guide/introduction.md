# Introduction

`@maximemrf/adonisjs-jwt` is an authentication guard for [AdonisJS](https://adonisjs.com) that issues and verifies JWT access tokens. It plugs into [`@adonisjs/auth`](https://docs.adonisjs.com/guides/authentication/introduction), so you protect routes with the `auth` middleware and read the user with `auth.getUserOrFail()`, like with the built-in guards.

## Features

- **Access tokens** signed with HMAC (default), RSA or ECDSA, with a 1 hour lifetime by default.
- **Refresh tokens** stored in the database, rotated on each use and revocable.
- **Bearer header or cookies**: the access and refresh tokens can be sent in the `Authorization` header or in `HttpOnly` cookies.
- **JWKS**: verify tokens issued by an external identity provider (Auth0, Keycloak, Kubernetes…).
- **Testing**: Japa's `loginAs` works out of the box.

## When to use it

Use JWTs when another service, a mobile app or a SPA on another domain needs to authenticate against your API without sharing a session, or when you need to verify tokens issued by an identity provider.

If your frontend and your API share the same domain, the AdonisJS [session guard](https://docs.adonisjs.com/guides/authentication/session-guard) is usually simpler. For long-lived API tokens that you can revoke one by one, see the [access tokens guard](https://docs.adonisjs.com/guides/authentication/access-tokens-guard).

## Compatibility

| Package version | AdonisJS version | Node.js     |
| --------------- | ---------------- | ----------- |
| `0.7.x`         | AdonisJS v6      | `>= 20.6.0` |
| `>= 0.8.x`      | AdonisJS v7      | `>= 24.0.0` |

Upgrading from 0.9? Read the [1.0 upgrade guide](/upgrading/1.0).
