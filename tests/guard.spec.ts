import { test } from '@japa/runner'
import { JwtGuard } from '../src/guard.js'
import { type BaseJwtContent, type JwtGuardUser } from '../src/types.js'
import { HttpContextFactory } from '@adonisjs/core/factories/http'
import { errors } from '@adonisjs/auth'
import { type JwtAuthFakeUser, JwtFakeUserProvider } from '../factories/main.js'
import jwt from 'jsonwebtoken'
import { timeTravel, createDatabase, createTables, TEST_SECRET } from '../tests/helpers.js'
import { BaseModel, column } from '@adonisjs/lucid/orm'
import { DbAccessTokensProvider } from '@adonisjs/auth/access_tokens'
import { tokensUserProvider } from '@adonisjs/auth/access_tokens'

test.group('Jwt guard | authenticate', () => {
  test('it should return a jwt token when user is authenticated with refresh token', async ({
    assert,
  }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const db = await createDatabase()
    await createTables(db)

    const guard = new JwtGuard(ctx, userProvider, {
      secret: TEST_SECRET,
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
        type: 'jwt_refresh_token',
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

    const tokens = await guard.generateWithRefreshToken()

    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
    // guard.user should be populated
    assert.exists(guard.user)
    assert.equal(guard.user!.id, user.id)

    // tokens should contain the new tokens
    assert.equal(tokens?.type, 'bearer')
    assert.exists(tokens?.token)
    assert.exists(tokens?.refreshToken)
    assert.isUndefined(tokens?.refreshTokenExpiresIn)

    // The old refresh token should be gone/invalid
    assert.notEqual(tokens?.refreshToken, refreshToken.value?.release())
  })

  test('throw error when refresh token user provider is not defined', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, {
      secret: TEST_SECRET,
    })

    const [result] = await Promise.allSettled([guard.generateWithRefreshToken()])
    assert.equal(result!.status, 'rejected')
    if (result!.status === 'rejected') {
      assert.instanceOf(result!.reason, errors.E_UNAUTHORIZED_ACCESS)
    }
    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when refresh token authorization header is missing', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()
    const db = await createDatabase()
    await createTables(db)

    const guard = new JwtGuard(ctx, userProvider, {
      secret: TEST_SECRET,
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
        type: 'jwt_refresh_token',
        tokenSecretLength: 40,
      })
    }

    const [result] = await Promise.allSettled([guard.generateWithRefreshToken()])
    assert.equal(result!.status, 'rejected')
    if (result!.status === 'rejected') {
      assert.instanceOf(result!.reason, errors.E_UNAUTHORIZED_ACCESS)
    }
    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when refresh token authorization header is invalid', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()
    const db = await createDatabase()
    await createTables(db)

    const guard = new JwtGuard(ctx, userProvider, {
      secret: TEST_SECRET,
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
        type: 'jwt_refresh_token',
        tokenSecretLength: 40,
      })
    }

    ctx.request.request.headers.authorization = `foo bar`
    const [result] = await Promise.allSettled([guard.generateWithRefreshToken()])
    assert.equal(result!.status, 'rejected')
    if (result!.status === 'rejected') {
      assert.instanceOf(result!.reason, errors.E_UNAUTHORIZED_ACCESS)
    }
    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('generateWithRefreshToken should allow subsequent calls with new token', async ({
    assert,
  }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const db = await createDatabase()
    await createTables(db)

    const guard = new JwtGuard(ctx, userProvider, {
      secret: TEST_SECRET,
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
        type: 'jwt_refresh_token',
        tokenSecretLength: 40,
      })
    }

    const user = await User.create({
      email: 'maxime@example.com',
      username: 'maxime',
      password: 'password',
    })
    const refreshToken = await User.refreshTokens.create(user)
    ctx.request.request.headers.authorization = `Bearer ${refreshToken.value?.release()}`

    // First call generates new tokens
    const tokens1 = await guard.generateWithRefreshToken()
    assert.exists(tokens1?.refreshToken)

    // Update header with NEW refresh token
    ctx.request.request.headers.authorization = `Bearer ${tokens1!.refreshToken}`

    // Second call should succeed with new token
    const tokens2 = await guard.generateWithRefreshToken()

    assert.isTrue(guard.isAuthenticated)
    assert.exists(tokens2?.refreshToken)
    assert.notEqual(tokens1!.refreshToken, tokens2!.refreshToken)
  })

  test('throw error when the refresh token used belongs to a unknown user', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()
    const db = await createDatabase()
    await createTables(db)
    const guard = new JwtGuard(ctx, userProvider, {
      secret: TEST_SECRET,
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
        type: 'jwt_refresh_token',
        tokenSecretLength: 40,
      })
    }

    const user = await User.create({
      email: 'maxime@example.com',
      username: 'maxime',
      password: 'password',
    })
    const refreshToken = await User.refreshTokens.create(user)
    await user.delete()
    ctx.request.request.headers.authorization = `Bearer ${refreshToken.value?.release()}`
    const [result] = await Promise.allSettled([guard.generateWithRefreshToken()])
    assert.equal(result!.status, 'rejected')
    if (result!.status === 'rejected') {
      assert.instanceOf(result!.reason, errors.E_UNAUTHORIZED_ACCESS)
    }
    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when the refresh token is invalid', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()
    const db = await createDatabase()
    await createTables(db)
    const guard = new JwtGuard(ctx, userProvider, {
      secret: TEST_SECRET,
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
        type: 'jwt_refresh_token',
        tokenSecretLength: 40,
      })
    }

    ctx.request.request.headers.authorization = `Bearer abcd`
    const [result] = await Promise.allSettled([guard.generateWithRefreshToken()])
    assert.equal(result!.status, 'rejected')
    if (result!.status === 'rejected') {
      assert.instanceOf(result!.reason, errors.E_UNAUTHORIZED_ACCESS)
    }
    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('it should return a token when user is authenticated', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, { secret: TEST_SECRET })
    ctx.request.request.headers.authorization = `Bearer ${jwt.sign({ userId: 1 }, TEST_SECRET)}`

    const authenticatedUser = await guard.authenticate()

    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)

    assert.equal(guard.user, authenticatedUser)
    assert.deepEqual(guard.getUserOrFail(), authenticatedUser)
  })

  test('it should return a cookie when user is authenticated', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, {
      secret: TEST_SECRET,
      useCookies: true,
    })
    const token = jwt.sign({ userId: 1 }, TEST_SECRET)
    ctx.request.cookiesList().token = token

    ctx.request.cookie = (key: string) => {
      const cookies = { token: token }
      return (cookies as Record<string, string>)[key]
    }

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
      secret: TEST_SECRET,
      useCookies: true,
      tokenName: 'custom',
    })
    const token = jwt.sign({ userId: 1 }, TEST_SECRET)
    ctx.request.cookiesList().custom = token

    ctx.request.cookie = (key: string) => {
      const cookies = { custom: token }
      return (cookies as Record<string, string>)[key]
    }

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
    const mySecret = 'customsecret-that-is-long-enough!!'

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
      secret: TEST_SECRET,
      expiresIn: '1h',
      content: jwtContentFn,
    })
    const user = await userProvider.findById(1)

    const content = jwtContentFn(user!)
    const tokenResponse: any = await guard.generate(user!.getOriginal())
    let decoded: any = {}

    if ('token' in tokenResponse) decoded = jwt.verify(tokenResponse.token, TEST_SECRET)
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
    const guard = new JwtGuard(ctx, userProvider, { secret: TEST_SECRET })
    const token = jwt.sign({ foo: 'bar' }, TEST_SECRET)

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

  test('throw error when the userId in payload is null or undefined', async ({ assert }) => {
    const userProvider = new JwtFakeUserProvider()
    const ctx = new HttpContextFactory().create()
    const guard = new JwtGuard(ctx, userProvider, { secret: TEST_SECRET })

    const tokenNull = jwt.sign({ userId: null }, TEST_SECRET)
    ctx.request.request.headers.authorization = `Bearer ${tokenNull}`
    const [resultNull] = await Promise.allSettled([guard.authenticate()])
    assert.equal(resultNull!.status, 'rejected')

    const tokenUndefined = jwt.sign({ userId: undefined }, TEST_SECRET)
    ctx.request.request.headers.authorization = `Bearer ${tokenUndefined}`
    const [resultUndefined] = await Promise.allSettled([guard.authenticate()])
    assert.equal(resultUndefined!.status, 'rejected')
  })

  test('throw error when the payload is not an object', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, { secret: TEST_SECRET })
    ctx.request.request.headers.authorization = `Bearer ${jwt.sign('foo', TEST_SECRET)}`
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
    const guard = new JwtGuard(ctx, userProvider, { secret: TEST_SECRET })
    ctx.request.request.headers.authorization = `Bearer ${jwt.sign({ userId: 999 }, TEST_SECRET)}`
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

    const guard = new JwtGuard(ctx, userProvider, { secret: TEST_SECRET })
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

    const guard = new JwtGuard(ctx, userProvider, { secret: TEST_SECRET })
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
    const token = await userProvider.createToken(user!.getOriginal(), TEST_SECRET, {
      expiresIn: '1h',
    })

    timeTravel(61 * 60)

    const guard = new JwtGuard(ctx, userProvider, { secret: TEST_SECRET })
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

    const guard = new JwtGuard(ctx, userProvider, { secret: TEST_SECRET })
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

    const guard = new JwtGuard(ctx, userProvider, { secret: TEST_SECRET })
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

    const guard = new JwtGuard(ctx, userProvider, { secret: TEST_SECRET })
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

    const guard = new JwtGuard(ctx, userProvider, { secret: TEST_SECRET })
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
    const token = await userProvider.createToken(user!.getOriginal(), TEST_SECRET, {
      expiresIn: '1h',
    })

    timeTravel(61 * 60)

    const guard = new JwtGuard(ctx, userProvider, { secret: TEST_SECRET })
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
    const token = await userProvider.createToken(user!.getOriginal(), TEST_SECRET)

    const guard = new JwtGuard(ctx, userProvider, { secret: TEST_SECRET })
    await assert.rejects(() => guard.authenticate(), 'Unauthorized access')

    ctx.request.request.headers.authorization = `Bearer ${token}`
    await assert.rejects(() => guard.authenticate(), 'Unauthorized access')

    assert.isUndefined(guard.user)
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('it should return a token when user is authenticated with lowercase bearer header', async ({
    assert,
  }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()
    const user = await userProvider.findById(1)
    const token = await userProvider.createToken(user!.getOriginal(), TEST_SECRET)

    const guard = new JwtGuard(ctx, userProvider, { secret: TEST_SECRET })
    ctx.request.request.headers.authorization = `bearer ${token}`

    const authenticatedUser = await guard.authenticate()

    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)

    assert.equal(guard.user, authenticatedUser)
    assert.deepEqual(guard.getUserOrFail(), authenticatedUser)
  })
})

test.group('Jwt guard | check', () => {
  test('return true when jwt token is valid', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const user = await userProvider.findById(1)
    const token = await userProvider.createToken(user!.getOriginal(), TEST_SECRET, {
      expiresIn: '1h',
    })
    const guard = new JwtGuard(ctx, userProvider, { secret: TEST_SECRET })

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
    const token = await userProvider.createToken(user!.getOriginal(), TEST_SECRET, {
      expiresIn: '1h',
    })
    const guard = new JwtGuard(ctx, userProvider, { secret: TEST_SECRET })

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

    const guard = new JwtGuard(ctx, userProvider, { secret: TEST_SECRET })
    const user = await userProvider.findById(1)
    const response = await guard.authenticateAsClient(user!.getOriginal())

    assert.property(response.headers, 'authorization')
    assert.match(
      response.headers!.authorization,
      /^Bearer ([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_\-\+\/=]*)/
    )
  })

  test('create bearer token for the given user with cookies', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, {
      secret: TEST_SECRET,
      useCookies: true,
    })
    const user = await userProvider.findById(1)
    const response = await guard.authenticateAsClient(user!.getOriginal())

    assert.property(response.headers, 'authorization')

    assert.match(
      response.headers!.authorization,
      /^Bearer ([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_\-\+\/=]*)/
    )
  })
})

test.group('Jwt guard | issuer and audience validation', () => {
  test('should sign and authenticate when issuer and audience match', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, {
      secret: TEST_SECRET,
      issuer: 'my-auth-server',
      audience: 'my-api',
    })

    const user = await userProvider.findById(1)
    const { token } = await guard.generate(user!.getOriginal())

    ctx.request.request.headers.authorization = `Bearer ${token}`
    const authenticatedUser = await guard.authenticate()

    assert.equal(authenticatedUser.id, 1)
  })

  test('should fail authentication when token issuer does not match', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, {
      secret: TEST_SECRET,
      issuer: 'expected-issuer',
    })

    const invalidToken = jwt.sign({ userId: 1 }, TEST_SECRET, { issuer: 'wrong-issuer' })
    ctx.request.request.headers.authorization = `Bearer ${invalidToken}`

    await assert.rejects(async () => await guard.authenticate(), /Unauthorized access/)
  })

  test('should fail authentication when token audience does not match', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, {
      secret: TEST_SECRET,
      audience: 'expected-audience',
    })

    const invalidToken = jwt.sign({ userId: 1 }, TEST_SECRET, { audience: 'wrong-audience' })
    ctx.request.request.headers.authorization = `Bearer ${invalidToken}`

    await assert.rejects(async () => await guard.authenticate(), /Unauthorized access/)
  })
})
