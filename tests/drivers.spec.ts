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
})
