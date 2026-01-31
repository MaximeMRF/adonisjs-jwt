import { test } from '@japa/runner'
import { JwtGuard } from '../src/jwt.js'
import { HttpContextFactory } from '@adonisjs/core/factories/http'
import { JwtFakeUserProvider } from '../factories/main.js'
import { BaseModel, column } from '@adonisjs/lucid/orm'
import { DbAccessTokensProvider } from '@adonisjs/auth/access_tokens'
import { createDatabase, createTables } from './helpers.js'
import { tokensUserProvider } from '@adonisjs/auth/access_tokens'

test('generate should return refresh token when configured', async ({ assert }) => {
  const ctx = new HttpContextFactory().create()
  const userProvider = new JwtFakeUserProvider()
  const db = await createDatabase()
  await createTables(db)

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

  const guard = new JwtGuard(ctx, userProvider, {
    secret: 'thisisasecret',
    refreshTokenUserProvider: tokensUserProvider({
      tokens: 'refreshTokens',
      async model() {
        return { default: User }
      },
    }),
  })

  const user = await User.create({
    email: 'test@example.com',
    username: 'test',
    password: 'password',
  })

  const tokens: any = await guard.generate(user)

  assert.exists(tokens.token)
  assert.exists(tokens.refreshToken)
  assert.equal(tokens.type, 'bearer')
})

test('generate should set cookies when configured', async ({ assert }) => {
  const ctx = new HttpContextFactory().create()
  const userProvider = new JwtFakeUserProvider()
  const db = await createDatabase()
  await createTables(db)

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

  const guard = new JwtGuard(ctx, userProvider, {
    secret: 'thisisasecret',
    useCookies: true,
    useCookiesForRefreshToken: true,
    refreshTokenUserProvider: tokensUserProvider({
      tokens: 'refreshTokens',
      async model() {
        return { default: User }
      },
    }),
  })

  const user = await User.create({
    email: 'cookie@example.com',
    username: 'cookie',
    password: 'password',
  })

  const tokens: any = await guard.generate(user)

  assert.exists(tokens.token)
  assert.exists(tokens.refreshToken)

  // Check cookies on response header
  const setCookie = ctx.response.getHeader('set-cookie') as string[]
  assert.isArray(setCookie)
  assert.isTrue(setCookie.some((c) => c.includes('token=')))
  assert.isTrue(setCookie.some((c) => c.includes('refreshToken=')))
})

test('revoke should invalidate refresh token', async ({ assert }) => {
  const ctx = new HttpContextFactory().create()
  const userProvider = new JwtFakeUserProvider()
  const db = await createDatabase()
  await createTables(db)

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

  const guard = new JwtGuard(ctx, userProvider, {
    secret: 'thisisasecret',
    refreshTokenUserProvider: tokensUserProvider({
      tokens: 'refreshTokens',
      async model() {
        return { default: User }
      },
    }),
  })

  const user = await User.create({
    email: 'revoke@example.com',
    username: 'revoke',
    password: 'password',
  })

  // Create token manually to simulate existing session
  const refreshToken = await User.refreshTokens.create(user)

  // Revoke passing token explicitly
  await guard.revoke(refreshToken.value!.release())

  // Verify token is gone from DB
  const dbToken = await User.refreshTokens.verify(refreshToken.value!)
  assert.isNull(dbToken)
})

test('findRefreshToken should find token in body', async ({ assert }) => {
  const ctx = new HttpContextFactory().create()
  const userProvider = new JwtFakeUserProvider()
  const db = await createDatabase()
  await createTables(db)

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

  const guard = new JwtGuard(ctx, userProvider, {
    secret: 'thisisasecret',
    refreshTokenUserProvider: tokensUserProvider({
      tokens: 'refreshTokens',
      async model() {
        return { default: User }
      },
    }),
  })

  const user = await User.create({
    email: 'body@example.com',
    username: 'body',
    password: 'password',
  })
  const refreshToken = await User.refreshTokens.create(user)

  // Put token in body
  ctx.request.setInitialBody({ refreshToken: refreshToken.value!.release() })

  const tokens = await guard.generateWithRefreshToken()
  assert.exists(tokens)
  assert.equal(guard.user!.id, user.id)
})

test('generate should return correct expires in when configured', async ({ assert }) => {
  const ctx = new HttpContextFactory().create()
  const userProvider = new JwtFakeUserProvider()
  const db = await createDatabase()
  await createTables(db)

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

  const guard = new JwtGuard(ctx, userProvider, {
    secret: 'thisisasecret',
    refreshTokenExpiresIn: '2h',
    refreshTokenUserProvider: tokensUserProvider({
      tokens: 'refreshTokens',
      async model() {
        return { default: User }
      },
    }),
  })

  const user = await User.create({
    email: 'expires@example.com',
    username: 'expires',
    password: 'password',
  })

  const tokens: any = await guard.generate(user)
  assert.equal(tokens.refreshTokenExpiresIn, '2h')
})

test('findRefreshToken should find token in cookie', async ({ assert }) => {
  const ctx = new HttpContextFactory().create()
  const userProvider = new JwtFakeUserProvider()
  const db = await createDatabase()
  await createTables(db)

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

  const guard = new JwtGuard(ctx, userProvider, {
    secret: 'thisisasecret',
    useCookiesForRefreshToken: true,
    refreshTokenUserProvider: tokensUserProvider({
      tokens: 'refreshTokens',
      async model() {
        return { default: User }
      },
    }),
  })

  const user = await User.create({
    email: 'cookie_lookup@example.com',
    username: 'cookie_lookup',
    password: 'password',
  })
  const refreshToken = await User.refreshTokens.create(user)

  // Put token in cookie - Mocking cookie lookup since we strictly look for cookie() result
  ctx.request.cookie = function (key) {
    if (key === 'refreshToken') return refreshToken.value!.release()
    return null
  }

  const tokens = await guard.generateWithRefreshToken()
  assert.exists(tokens)
  assert.equal(guard.user!.id, user.id)
})

test('revoke should throw error when provider is not defined', async ({ assert }) => {
  const ctx = new HttpContextFactory().create()
  const userProvider = new JwtFakeUserProvider()

  const guard = new JwtGuard(ctx, userProvider, {
    secret: 'thisisasecret',
  })

  await assert.rejects(async () => {
    await guard.revoke('some-token')
  }, 'Unauthorized access')
})

// test('revoke should return silently when token not found', async ({ assert }) => {
//   const ctx = new HttpContextFactory().create()
//   const userProvider = new JwtFakeUserProvider()

//   // Create guard with provider but don't provide any token in request
//   const guard = new JwtGuard(ctx, userProvider, {
//     secret: 'thisisasecret',
//     refreshTokenUserProvider: tokensUserProvider({
//       tokens: 'refreshTokens',
//       async model() {
//         // @ts-ignore
//         return { default: {} }
//       },
//     }),
//   })

//   // Should not throw
//   await guard.revoke()
// })

test('generateWithRefreshToken should fail when invalidateToken fails', async ({ assert }) => {
  const ctx = new HttpContextFactory().create()
  const userProvider = new JwtFakeUserProvider()
  const db = await createDatabase()
  await createTables(db)

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

  const tokenProvider = tokensUserProvider({
    tokens: 'refreshTokens',
    async model() {
      return { default: User }
    },
  })

  const guard = new JwtGuard(ctx, userProvider, {
    secret: 'thisisasecret',
    refreshTokenUserProvider: tokenProvider,
  })

  const user = await User.create({
    email: 'fail_invalidate@example.com',
    username: 'fail_invalidate',
    password: 'password',
  })
  const refreshToken = await User.refreshTokens.create(user)

  tokenProvider.invalidateToken = async () => false

  ctx.request.request.headers.authorization = `Bearer ${refreshToken.value!.release()}`

  await assert.rejects(async () => {
    await guard.generateWithRefreshToken()
  }, 'Unauthorized access')
})
