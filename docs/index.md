---
layout: home

hero:
  name: AdonisJS JWT
  text: JWT authentication for AdonisJS
  tagline: An auth guard that issues and verifies JWT access tokens, with refresh tokens, cookies, asymmetric keys and JWKS.
  actions:
    - theme: brand
      text: Get started
      link: /guide/introduction
    - theme: alt
      text: Upgrading to 1.0
      link: /upgrading/1.0
    - theme: alt
      text: GitHub
      link: https://github.com/MaximeMRF/adonisjs-jwt

features:
  - title: Plugs into @adonisjs/auth
    details: A regular auth guard. Use the auth middleware, auth.use('jwt'), getUserOrFail() and Japa's loginAs like with any other guard.
  - title: Refresh tokens
    details: Rotating refresh tokens stored in the database, with replay protection, expiration and revocation.
  - title: Bearer header or cookies
    details: Send the access token in the Authorization header, in an HttpOnly cookie, or both.
  - title: HMAC, RSA, ECDSA and JWKS
    details: Sign with a secret derived from your app key, with your own key pair, or verify tokens issued by an identity provider.
---
