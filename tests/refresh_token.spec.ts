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
