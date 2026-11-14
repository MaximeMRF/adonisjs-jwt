# Security policy

## Supported versions

| Version                | Supported         |
| ---------------------- | ----------------- |
| 1.x                    | ✅                |
| < 1.0 (0.x, alpha, rc) | ❌ upgrade to 1.x |

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through
[GitHub private vulnerability reporting](https://github.com/MaximeMRF/adonisjs-jwt/security/advisories/new).

Include the version, the guard configuration (without secrets) and the steps
to reproduce. You can expect an acknowledgment within 7 days. Once a fix is
released, a GitHub security advisory is published, with credit to the reporter
unless they prefer otherwise.

## Scope

In scope: anything that lets a request authenticate without valid credentials,
use another user's or another guard's tokens, keep a revoked refresh token
working, or bypass the documented checks (signature, expiration, issuer,
audience, abilities).

Out of scope:

- Attacks that require the signing secret or private key.
- Access tokens staying valid until they expire after a logout: they are
  stateless by design (see the [Security guide](https://maximemrf.github.io/adonisjs-jwt/guide/security)).
  Keep `tokenExpiresIn` short.
- Vulnerabilities in dependencies (`jsonwebtoken`, `jwks-rsa`, `@adonisjs/*`):
  report them upstream, and open an issue here if this package needs to bump
  a version.
