import { test } from '@japa/runner'
import { JwtGuard } from '../src/jwt.js'
import { BaseJwtContent, JwtGuardUser } from '../src/types.js'
import { HttpContextFactory } from '@adonisjs/core/factories/http'
import { errors } from '@adonisjs/auth'
import { JwtAuthFakeUser, JwtFakeUserProvider } from '../factories/main.js'
import jwt from 'jsonwebtoken'
import { timeTravel } from '../tests/helpers.js'
import { BaseModel, column } from '@adonisjs/lucid/orm'
import { DbAccessTokensProvider } from '@adonisjs/auth/access_tokens'
import { createDatabase, createTables } from '../tests/helpers.js'
import { tokensUserProvider } from '@adonisjs/auth/access_tokens'

test.group('Jwt guard | authenticate', () => {
  test('it should return a jwt token when user is authenticated with refresh token', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const db = await createDatabase()
    await createTables(db)

    const guard = new JwtGuard(ctx, userProvider, {
      secret: 'thisisasecret',
      refreshTokenUserProvider: tokensUserProvider({
        tokens: 'refreshTokens',
        async model() {
          return {
            default: User,
          }
        },
      }),
    })

    class User extends BaseModel {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string

      static refreshTokens = DbAccessTokensProvider.forModel(User, {
        prefix: 'rt_',
        table: 'jwt_refresh_tokens',
        type: 'auth_token',
        tokenSecretLength: 40,
      })
    }

    const user = await User.create({
      email: 'max@example.com',
      username: 'max',
      password: 'secret',
    })

    const refreshToken = await User.refreshTokens.create(user)

    ctx.request.request.headers.authorization = `Bearer ${refreshToken.value?.release()}`

    const userAuthenticated = await guard.authenticateWithRefreshToken()

    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
    assert.equal(guard.user, userAuthenticated)
    assert.deepEqual(guard.getUserOrFail(), userAuthenticated)
    assert.exists(userAuthenticated.currentToken)
    assert.exists(refreshToken.value?.release())
  })

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

  test('it should return a cookie when user is authenticated', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, { secret: 'thisisasecret', useCookies: true })
    ctx.request.request.headers.cookie = 'token=' + jwt.sign({ userId: 1 }, 'thisisasecret')

    const authenticatedUser = await guard.authenticate()

    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)

    assert.equal(guard.user, authenticatedUser)
    assert.deepEqual(guard.getUserOrFail(), authenticatedUser)
  })

  test('it should return a cookie with custom name token when user is authenticated', async ({
    assert,
  }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, {
      secret: 'thisisasecret',
      useCookies: true,
      tokenName: 'custom',
    })
    ctx.request.request.headers.cookie = 'custom=' + jwt.sign({ userId: 1 }, 'thisisasecret')

    const authenticatedUser = await guard.authenticate()

    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)

    assert.equal(guard.user, authenticatedUser)
    assert.deepEqual(guard.getUserOrFail(), authenticatedUser)
  })

  test('it should return a token when the custom secret key is used for signing', async ({
    assert,
  }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()
    const mySecret = 'customsecret'

    const guard = new JwtGuard(ctx, userProvider, {
      secret: mySecret,
    })
    ctx.request.request.headers.authorization = `Bearer ${jwt.sign({ userId: 1 }, mySecret)}`

    const authenticatedUser = await guard.authenticate()

    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)

    assert.equal(guard.user, authenticatedUser)
    assert.deepEqual(guard.getUserOrFail(), authenticatedUser)
  })

  test('it should return the content function provided when generating jwt', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    interface CustomJwtContent extends BaseJwtContent {
      otherProperty: string
    }

    const jwtContentFn = (user: JwtGuardUser<JwtAuthFakeUser>): CustomJwtContent => ({
      userId: user.getId(),
      otherProperty: 'random',
    })
    const guard = new JwtGuard(ctx, userProvider, {
      secret: 'thisisasecret',
      expiresIn: '1h',
      content: jwtContentFn,
    })
    const user = await userProvider.findById(1)

    const content = jwtContentFn(user!)
    const tokenResponse: any = await guard.generate(user!.getOriginal())
    let decoded: any = {}

    if ('token' in tokenResponse) decoded = jwt.verify(tokenResponse.token, 'thisisasecret')
    else assert.fail('Token response is not an object when useCookies is false')

    assert.equal(tokenResponse.type, 'bearer')
    assert.exists(tokenResponse.token)
    assert.equal(tokenResponse.expiresIn, '1h')

    assert.equal(decoded.userId, content.userId)
    assert.equal(decoded.otherProperty, content.otherProperty)
  })

  test('throw error when the userId is not found in the payload', async ({ assert }) => {
    const userProvider = new JwtFakeUserProvider()
    const ctx = new HttpContextFactory().create()
    const guard = new JwtGuard(ctx, userProvider, { secret: 'thisisasecret' })
    const token = jwt.sign({ foo: 'bar' }, 'thisisasecret')

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

  test('throw error when the payload is not an object', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, { secret: 'thisisasecret' })
    ctx.request.request.headers.authorization = `Bearer ${jwt.sign('foo', 'thisisasecret')}`
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

  test('throw error when the payload contains a userId that does not exist', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()
    const guard = new JwtGuard(ctx, userProvider, { secret: 'thisisasecret' })
    ctx.request.request.headers.authorization = `Bearer ${jwt.sign({ userId: 999 }, 'thisisasecret')}`
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

  test('throw error when cookie header is invalid', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, { secret: 'thisisasecret' })
    ctx.request.request.headers.cookie = 'foo bar'
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

  test('throw error when cookie token is empty', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, { secret: 'thisisasecret' })
    ctx.request.request.headers.cookie = 'token='
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

  test('throw error when cookie token has been expired', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()
    const user = await userProvider.findById(1)
    const token = await userProvider.createToken(user!.getOriginal(), 'thisisasecret', {
      expiresIn: '1h',
    })

    timeTravel(61 * 60)

    const guard = new JwtGuard(ctx, userProvider, { secret: 'thisisasecret' })
    ctx.request.request.headers.cookie = `token=${token}`
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

  test('throw error when authorization header and cookie header are missing', async ({
    assert,
  }) => {
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
      currentToken: token,
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
