import { test } from '@japa/runner'
import { generateKeyPairSync } from 'node:crypto'
import jwt from 'jsonwebtoken'
import { JwtGuard } from '../src/jwt.js'
import { JwtFakeUserProvider } from '../factories/main.js'
import { HttpContextFactory } from '@adonisjs/core/factories/http'
import { errors } from '@adonisjs/auth'

function rsaPemPair() {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
  return { publicKey, privateKey }
}

test.group('Jwt guard | asymmetric (RSA)', () => {
  test('generate and authenticate with RS256', async ({ assert }) => {
    const { publicKey, privateKey } = rsaPemPair()
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, {
      privateKey,
      publicKey,
      algorithm: 'RS256',
    })

    const user = await userProvider.findById(1)
    const { token } = await guard.generate(user!.getOriginal())

    const header = JSON.parse(Buffer.from(token.split('.')[0]!, 'base64url').toString())
    assert.equal(header.alg, 'RS256')

    ctx.request.request.headers.authorization = `Bearer ${token}`
    await guard.authenticate()

    assert.isTrue(guard.isAuthenticated)
    assert.equal(guard.user!.id, 1)
  })

  test('rejects HS256 token when using asymmetric guard', async ({ assert }) => {
    const { publicKey, privateKey } = rsaPemPair()
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, {
      privateKey,
      publicKey,
      algorithm: 'RS256',
    })

    const hs256Token = jwt.sign({ userId: 1 }, 'symmetric-secret')
    ctx.request.request.headers.authorization = `Bearer ${hs256Token}`

    const [result] = await Promise.allSettled([guard.authenticate()])
    assert.equal(result!.status, 'rejected')
    if (result!.status === 'rejected') {
      assert.instanceOf(result!.reason, errors.E_UNAUTHORIZED_ACCESS)
    }
  })

  test('throws when asymmetric fields are only partially set', async ({ assert }) => {
    const { publicKey, privateKey } = rsaPemPair()
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    assert.throws(
      () =>
        new JwtGuard(ctx, userProvider, {
          privateKey,
          publicKey,
        }),
      /privateKey.*publicKey.*algorithm/
    )
  })
})
