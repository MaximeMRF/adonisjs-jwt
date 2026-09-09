import { test } from '@japa/runner'
import { SymmetricDriver } from '../src/drivers/symmetric.js'
import { AsymmetricDriver } from '../src/drivers/asymmetric.js'
import { JwksDriver } from '../src/drivers/jwks.js'
import { JwtGuard } from '../src/guard.js'
import { HttpContextFactory } from '@adonisjs/core/factories/http'
import { JwtFakeUserProvider } from '../factories/main.js'
import { generateKeyPairSync } from 'node:crypto'

test.group('JWT Drivers', () => {
  test('SymmetricDriver should throw error if secret is missing', ({ assert }) => {
    assert.throws(
      () => new SymmetricDriver({ secret: '' }),
      'Symmetric JWT driver requires a secret key'
    )
  })

  test('SymmetricDriver should sign and verify correctly', ({ assert }) => {
    const driver = new SymmetricDriver({ secret: 'secret' })
    const payload = { userId: 1 }
    const token = driver.sign(payload)
    assert.exists(token)

    const verified = driver.verify(token) as any
    assert.equal(verified.userId, 1)
  })

  test('AsymmetricDriver should sign with expiresIn options', ({ assert }) => {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    })

    const driver = new AsymmetricDriver({
      privateKey,
      publicKey,
      algorithm: 'RS256',
    })

    const payload = { userId: 1 }
    const token = driver.sign(payload, { expiresIn: '1h' })
    assert.exists(token)

    const verified = driver.verify(token) as any
    assert.equal(verified.userId, 1)
  })

  test('JwksDriver sign should throw error', ({ assert }) => {
    const driver = new JwksDriver({ jwksUri: 'https://example.com' })
    assert.throws(
      () => driver.sign({ userId: 1 }),
      "You can't use the auth.generate method with jwks"
    )
  })

  test('JwtGuard should support custom driver injection', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const mockDriver = {
      canSign: true,
      sign: () => 'mocked-token',
      verify: () => ({ userId: 1 }),
    }

    const guard = new JwtGuard(ctx, userProvider, {
      driver: mockDriver,
    } as any)

    const user = await userProvider.findById(1)
    const { token } = await guard.generate(user!.getOriginal())
    assert.equal(token, 'mocked-token')

    ctx.request.request.headers.authorization = 'Bearer mocked-token'
    const authenticatedUser = await guard.authenticate()
    assert.equal(authenticatedUser.id, 1)
  })

  test('jwtGuard config provider should work without specifying content', async ({ assert }) => {
    const { jwtGuard } = await import('../src/define_config.js')
    const userProvider = new JwtFakeUserProvider()

    const provider = jwtGuard({
      provider: userProvider,
      secret: 'mysecret',
    })

    const fakeApp = {
      config: {
        get: () => ({ release: () => 'appkey' }),
      },
    } as any

    const guardFactory = await provider.resolver('jwt', fakeApp)
    const ctx = new HttpContextFactory().create()
    const guard = guardFactory(ctx)

    const user = await userProvider.findById(1)
    const tokenResult = await guard.generate(user!.getOriginal())
    assert.exists(tokenResult.token)
  })

  test('jwtGuard config provider should resolve asymmetric driver and jwks driver', async ({
    assert,
  }) => {
    const { jwtGuard } = await import('../src/define_config.js')
    const userProvider = new JwtFakeUserProvider()
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    })

    const fakeApp = {
      config: {
        get: () => ({ release: () => 'appkey' }),
      },
    } as any

    const asymProvider = jwtGuard({
      provider: userProvider,
      privateKey,
      publicKey,
      algorithm: 'RS256',
    })
    const asymFactory = await asymProvider.resolver('jwt', fakeApp)
    assert.exists(asymFactory)

    const jwksProvider = jwtGuard({
      provider: userProvider,
      jwks: { jwksUri: 'https://example.com' },
    })
    const jwksFactory = await jwksProvider.resolver('jwt', fakeApp)
    assert.exists(jwksFactory)

    await assert.rejects(
      async () =>
        await jwtGuard({
          provider: userProvider,
          privateKey: 'invalid',
          publicKey: 'invalid',
          algorithm: 'RS256',
        }).resolver('jwt', fakeApp),
      /JWT guard asymmetric key validation failed/
    )
  })
})
