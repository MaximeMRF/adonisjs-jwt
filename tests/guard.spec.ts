import { test } from '@japa/runner'
import { JwtGuard } from '../src/jwt.js'
import { HttpContextFactory } from '@adonisjs/core/factories/http'
import { errors } from '@adonisjs/auth'
import { JwtFakeUserProvider } from '../factories/main.js'
import jwt from 'jsonwebtoken'
import { timeTravel } from '../tests/helpers.js'

test.group('Jwt guard | authenticate', () => {
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
    if (result!.status === 'rejected') {
      assert.instanceOf(result!.reason, errors.E_UNAUTHORIZED_ACCESS)
    }

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')

    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when bearer token has been expired', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()
    const user = await userProvider.findById(1)
    const token = await userProvider.createToken(user!.getOriginal(), 'thisisasecret', {
      expiresIn: '1h',
    })

    timeTravel(61 * 60)

    const guard = new JwtGuard(ctx, userProvider, { secret: 'thisisasecret' })
    ctx.request.request.headers.authorization = `Bearer ${token}`
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

  test('multiple calls to authenticate method should be a noop', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()
    const user = await userProvider.findById(1)
    const token = await userProvider.createToken(user!.getOriginal(), 'thisisasecret', {
      expiresIn: '1h',
    })

    const guard = new JwtGuard(ctx, userProvider, { secret: 'thisisasecret' })
    await assert.rejects(() => guard.authenticate(), 'Unauthorized access')

    ctx.request.request.headers.authorization = `Bearer ${token}`
    await assert.rejects(() => guard.authenticate(), 'Unauthorized access')

    assert.isUndefined(guard.user)
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })
})

test.group('Jwt guard | check', () => {
  test('return true when jwt token is valid', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const user = await userProvider.findById(1)
    const token = await userProvider.createToken(user!.getOriginal(), 'thisisasecret', {
      expiresIn: '1h',
    })
    const guard = new JwtGuard(ctx, userProvider, { secret: 'thisisasecret' })

    ctx.request.request.headers.authorization = `Bearer ${token}`
    const isLoggedIn = await guard.check()

    assert.isTrue(isLoggedIn)
    assert.deepEqual(guard.user, {
      id: 1,
      email: 'maxou@max.com',
      password: 'secret',
    })
    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('return false when jwt token is invalid', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const user = await userProvider.findById(1)
    const token = await userProvider.createToken(user!.getOriginal(), 'thisisasecret', {
      expiresIn: '1h',
    })
    const guard = new JwtGuard(ctx, userProvider, { secret: 'thisisasecret' })

    timeTravel(61 * 60)

    ctx.request.request.headers.authorization = `Bearer ${token}`
    const isLoggedIn = await guard.check()

    assert.isFalse(isLoggedIn)
    assert.isUndefined(guard.user)
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })
})

test.group('Jwt tokens guard | authenticateAsClient', () => {
  test('create bearer token for the given user', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, { secret: 'thisisasecret' })
    const user = await userProvider.findById(1)
    const response = await guard.authenticateAsClient(user!.getOriginal())

    assert.property(response.headers, 'authorization')
    assert.match(
      response.headers!.authorization,
      /^Bearer ([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_\-\+\/=]*)/
    )
  })
})
