import { test } from '@japa/runner'
import { JwtGuard } from '../src/jwt.js'
import { HttpContextFactory } from '@adonisjs/core/factories/http'
import { errors } from '@adonisjs/auth'
import { JwtFakeUserProvider } from '../factories/main.js'
import jwt from 'jsonwebtoken'

test.group('Guard', () => {
  test('it should return a token when user is authenticated', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, { secret: 'thisisasecret' })
    ctx.request.request.headers.authorization = `Bearer ${jwt.sign({ userId: 1 }, 'thisisasecret')}`

    const authenticatedUser = await guard.authenticate()

    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)

    assert.equal(guard.user, authenticatedUser)
    assert.deepEqual(guard.getUserOrFail(), authenticatedUser)
  })

  test('throw error when authorization header is missing', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, { secret: 'thisisasecret' })
    const [result] = await Promise.allSettled([guard.authenticate()])

    assert.equal(result!.status, 'rejected')
    if (result!.status === 'rejected') {
      assert.instanceOf(result!.reason, errors.E_UNAUTHORIZED_ACCESS)
    }

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')

    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when authorization header is invalid', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, { secret: 'thisisasecret' })
    ctx.request.request.headers.authorization = 'foo bar'
    const [result] = await Promise.allSettled([guard.authenticate()])

    assert.equal(result!.status, 'rejected')
    if (result!.status === 'rejected') {
      assert.instanceOf(result!.reason, errors.E_UNAUTHORIZED_ACCESS)
    }

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')

    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when bearer token is empty', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, { secret: 'thisisasecret' })
    ctx.request.request.headers.authorization = 'Bearer '
    const [result] = await Promise.allSettled([guard.authenticate()])

    assert.equal(result!.status, 'rejected')
    if (result!.status === 'rejected') {
      assert.instanceOf(result!.reason, errors.E_UNAUTHORIZED_ACCESS)
    }

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')

    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when bearer token is invalid', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, { secret: 'thisisasecret' })
    ctx.request.request.headers.authorization = 'Bearer coucou'
    const [result] = await Promise.allSettled([guard.authenticate()])

    assert.equal(result!.status, 'rejected')
    console.log(result)
    if (result!.status === 'rejected') {
      assert.instanceOf(result!.reason, errors.E_UNAUTHORIZED_ACCESS)
    }

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')

    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })
})
