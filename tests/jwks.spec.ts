import { test } from '@japa/runner'
import { JwtGuard } from '../src/jwt.js'
import { HttpContextFactory } from '@adonisjs/core/factories/http'
import { JwtFakeUserProvider } from '../factories/main.js'
import jwt from 'jsonwebtoken'
import nock from 'nock'
import crypto from 'node:crypto'

test.group('Jwt guard | JWKS', (group) => {
  group.each.teardown(() => {
    nock.cleanAll()
  })

  const generateKeys = () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    })

    const jwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' })
    const kid = 'test-key-id'
    return {
      privateKey,
      publicKey,
      jwk: { ...jwk, kid, alg: 'RS256', use: 'sig' },
      kid,
    }
  }

  test('authenticate using JWKS', async ({ assert }) => {
    const { privateKey, jwk, kid } = generateKeys()
    const jwksUri = 'https://fake-auth.com/.well-known/jwks.json'

    nock('https://fake-auth.com')
      .get('/.well-known/jwks.json')
      .reply(200, { keys: [jwk] })

    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    // Ensure user exists in provider (JwtFakeUserProvider usually has id:1 by default or we can look it up)
    // Actually JwtFakeUserProvider.findById(1) returns a user.

    const guard = new JwtGuard(ctx, userProvider, {
      secret: 'ignored',
      jwks: { jwksUri },
    })

    const token = jwt.sign({ userId: 1 }, privateKey, {
      algorithm: 'RS256',
      keyid: kid,
      header: { kid, alg: 'RS256' },
    })

    ctx.request.request.headers.authorization = `Bearer ${token}`

    const user = await guard.authenticate()
    assert.equal(user.id, 1)
    assert.isTrue(guard.isAuthenticated)
  })

  test('fail when JWKS fetch fails', async ({ assert }) => {
    const { privateKey, kid } = generateKeys()
    const jwksUri = 'https://fake-auth.com/.well-known/jwks.json'

    nock('https://fake-auth.com').get('/.well-known/jwks.json').reply(500)

    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, {
      secret: 'ignored',
      jwks: { jwksUri },
    })

    const token = jwt.sign({ userId: 1 }, privateKey, {
      algorithm: 'RS256',
      keyid: kid,
      header: { kid, alg: 'RS256' },
    })

    ctx.request.request.headers.authorization = `Bearer ${token}`

    await assert.rejects(async () => {
      await guard.authenticate()
    })
  })

  test('fail when kid matches no key', async ({ assert }) => {
    const { privateKey, jwk } = generateKeys()
    const jwksUri = 'https://fake-auth.com/.well-known/jwks.json'

    nock('https://fake-auth.com')
      .get('/.well-known/jwks.json')
      .reply(200, { keys: [jwk] })

    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, {
      secret: 'ignored',
      jwks: { jwksUri },
    })

    // Sign with a kid that definitely doesn't match the one in JWK
    const token = jwt.sign({ userId: 1 }, privateKey, {
      algorithm: 'RS256',
      keyid: 'other-kid',
      header: { kid: 'other-kid', alg: 'RS256' },
    })

    ctx.request.request.headers.authorization = `Bearer ${token}`

    await assert.rejects(async () => {
      await guard.authenticate()
    })
  })

  test('fail when token has no kid header', async ({ assert }) => {
    const { privateKey } = generateKeys()
    const jwksUri = 'https://fake-auth.com/.well-known/jwks.json'

    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, {
      secret: 'ignored',
      jwks: { jwksUri },
    })

    const token = jwt.sign({ userId: 1 }, privateKey, {
      algorithm: 'RS256',
    })

    ctx.request.request.headers.authorization = `Bearer ${token}`

    await assert.rejects(async () => {
      await guard.authenticate()
    })
  })

  test('should throw error when calling generate with jwks enabled', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()
    const user = await userProvider.findById(1)

    const guard = new JwtGuard(ctx, userProvider, {
      secret: 'ignored',
      jwks: { jwksUri: 'https://example.com' },
    })

    await assert.rejects(async () => {
      await guard.generate(user!.getOriginal())
    }, "You can't use the auth.generate method with jwks")
  })

  test('should throw error when calling generateWithRefreshToken with jwks enabled', async ({
    assert,
  }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, {
      secret: 'ignored',
      jwks: { jwksUri: 'https://example.com' },
    })

    await assert.rejects(async () => {
      await guard.generateWithRefreshToken()
    }, 'JWKS is not supported for refresh token')
  })

  test('should return the jwks client', async ({ assert }) => {
    const { JwksManager } = await import('../src/jwks.js')
    const manager = new JwksManager({
      jwksUri: 'https://fake-auth.com/.well-known/jwks.json',
    })
    const client = manager.getClient()
    assert.exists(client)
    assert.property(client, 'getSigningKey')
  })
})
