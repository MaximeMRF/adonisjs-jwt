import { test } from '@japa/runner'
import { JwtGuard } from '../src/guard.js'
import { JwksDriver } from '../src/drivers/jwks.js'
import { jwtGuard } from '../src/define_config.js'
import { HttpContextFactory } from '@adonisjs/core/factories/http'
import { JwtFakeUserProvider } from '../factories/main.js'
import { BaseModel, column } from '@adonisjs/lucid/orm'
import { DbAccessTokensProvider, tokensUserProvider } from '@adonisjs/auth/access_tokens'
import { createDatabase, createTables, timeTravel, TEST_SECRET } from './helpers.js'
import jwt from 'jsonwebtoken'
import nock from 'nock'
import crypto from 'node:crypto'

const APP_KEY = 'app-key-with-at-least-32-characters'

function fakeApp(appKey?: string) {
  return {
    config: {
      get: () => (appKey === undefined ? undefined : { release: () => appKey }),
    },
  } as any
}

async function setupRefreshTokens() {
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

  const refreshTokenUserProvider = tokensUserProvider({
    tokens: 'refreshTokens',
    async model() {
      return { default: User }
    },
  })

  const user = await User.create({
    email: 'security@example.com',
    username: 'security',
    password: 'password',
  })

  return { User, user, refreshTokenUserProvider }
}

test.group('Security | access token lifetime', () => {
  test('access tokens expire after 1 hour when tokenExpiresIn is not set', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()
    const guard = new JwtGuard(ctx, userProvider, { secret: TEST_SECRET })

    const user = await userProvider.findById(1)
    const result = await guard.generate(user!.getOriginal())
    const payload = jwt.decode(result.token) as jwt.JwtPayload

    assert.equal(result.expiresIn, '1h')
    assert.equal(payload.exp! - payload.iat!, 60 * 60)
  })

  test('throw when tokenExpiresIn is {value}')
    .with([{ value: 0 }, { value: -60 }, { value: Number.NaN }])
    .run(({ assert }, { value }) => {
      const ctx = new HttpContextFactory().create()
      const userProvider = new JwtFakeUserProvider()

      assert.throws(
        () => new JwtGuard(ctx, userProvider, { secret: TEST_SECRET, tokenExpiresIn: value }),
        'JwtGuard `tokenExpiresIn` must be a positive number of seconds'
      )
    })

  test('throw at startup when tokenExpiresIn is not positive', async ({ assert }) => {
    await assert.rejects(
      () =>
        jwtGuard({
          provider: new JwtFakeUserProvider(),
          secret: TEST_SECRET,
          tokenExpiresIn: 0,
        }).resolver('jwt', fakeApp(APP_KEY)),
      'JWT guard `tokenExpiresIn` must be a positive number of seconds'
    )
  })
})

test.group('Security | app key fallback', () => {
  test('tokens are not signed with the raw app key', async ({ assert }) => {
    const userProvider = new JwtFakeUserProvider()
    const factory = await jwtGuard({ provider: userProvider }).resolver('jwt', fakeApp(APP_KEY))

    const user = await userProvider.findById(1)
    const { token } = await factory(new HttpContextFactory().create()).generate(user!.getOriginal())

    assert.throws(() => jwt.verify(token, APP_KEY), 'invalid signature')
  })

  test('a guard does not accept tokens issued by another guard', async ({ assert }) => {
    const userProvider = new JwtFakeUserProvider()
    const userFactory = await jwtGuard({ provider: userProvider }).resolver('jwt', fakeApp(APP_KEY))
    const adminFactory = await jwtGuard({ provider: userProvider }).resolver(
      'admin',
      fakeApp(APP_KEY)
    )

    const user = await userProvider.findById(1)
    const { token } = await userFactory(new HttpContextFactory().create()).generate(
      user!.getOriginal()
    )

    const userCtx = new HttpContextFactory().create()
    userCtx.request.request.headers.authorization = `Bearer ${token}`
    assert.isTrue(await userFactory(userCtx).check())

    const adminCtx = new HttpContextFactory().create()
    adminCtx.request.request.headers.authorization = `Bearer ${token}`
    assert.isFalse(await adminFactory(adminCtx).check())
  })

  test('throw at startup when the app key is {case}')
    .with([
      { case: 'missing', appKey: undefined },
      { case: 'shorter than 32 characters', appKey: 'short-app-key' },
    ])
    .run(async ({ assert }, { appKey }) => {
      await assert.rejects(
        () => jwtGuard({ provider: new JwtFakeUserProvider() }).resolver('jwt', fakeApp(appKey)),
        'JWT guard requires `app.appKey` to be at least 32 characters when no `secret` is configured'
      )
    })

  test('do not read the app key when a secret is configured', async ({ assert }) => {
    const factory = await jwtGuard({
      provider: new JwtFakeUserProvider(),
      secret: TEST_SECRET,
    }).resolver('jwt', fakeApp())

    assert.isFunction(factory)
  })
})

test.group('Security | JWKS', (group) => {
  group.each.teardown(() => {
    nock.cleanAll()
  })

  const jwksUri = 'https://fake-auth.com/.well-known/jwks.json'
  const claims = { issuer: 'jwks-issuer', audience: 'jwks-audience' }

  test('throw at startup when JWKS is used without {missing}')
    .with([
      { missing: 'audience', options: { issuer: 'jwks-issuer' } },
      { missing: 'issuer', options: { audience: 'jwks-audience' } },
      { missing: 'a non-empty audience', options: { issuer: 'jwks-issuer', audience: [] } },
    ])
    .run(async ({ assert }, { options }) => {
      await assert.rejects(
        () =>
          jwtGuard({
            provider: new JwtFakeUserProvider(),
            jwks: { jwksUri },
            ...options,
          }).resolver('jwt', fakeApp()),
        /JWT guard JWKS validation failed: `issuer` and `audience` are required/
      )
    })

  test('rate limit JWKS fetches triggered by unknown kids', async ({ assert }) => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    })
    const jwk = { ...crypto.createPublicKey(publicKey).export({ format: 'jwk' }), kid: 'known' }

    let fetches = 0
    nock('https://fake-auth.com')
      .persist()
      .get('/.well-known/jwks.json')
      .reply(() => {
        fetches++
        return [200, { keys: [jwk] }]
      })

    const driver = new JwksDriver({ jwksUri }, claims)
    const userProvider = new JwtFakeUserProvider()

    for (let i = 0; i < 25; i++) {
      const kid = crypto.randomUUID()
      const token = jwt.sign({ userId: 1 }, privateKey, {
        algorithm: 'RS256',
        keyid: kid,
        ...claims,
      })
      const ctx = new HttpContextFactory().create()
      ctx.request.request.headers.authorization = `Bearer ${token}`
      assert.isFalse(await new JwtGuard(ctx, userProvider, { driver }).check())
    }

    assert.isAtMost(fetches, 10)
  })
})

test.group('Security | refresh tokens', () => {
  test('revoke clears the access and refresh token cookies', async ({ assert }) => {
    const { refreshTokenUserProvider } = await setupRefreshTokens()
    const ctx = new HttpContextFactory().create()

    const guard = new JwtGuard(ctx, new JwtFakeUserProvider(), {
      secret: TEST_SECRET,
      useCookies: true,
      useCookiesForRefreshToken: true,
      refreshTokenUserProvider,
    })

    await guard.revoke()

    const setCookie = ctx.response.getHeader('set-cookie') as string[]
    assert.isArray(setCookie)
    assert.isTrue(setCookie.some((c) => c.startsWith('token=;') && c.includes('Max-Age=0')))
    assert.isTrue(setCookie.some((c) => c.startsWith('refreshToken=;') && c.includes('Max-Age=0')))
  })

  test('revoke does not touch cookies when cookies are not used', async ({ assert }) => {
    const { refreshTokenUserProvider } = await setupRefreshTokens()
    const ctx = new HttpContextFactory().create()

    const guard = new JwtGuard(ctx, new JwtFakeUserProvider(), {
      secret: TEST_SECRET,
      refreshTokenUserProvider,
    })

    await guard.revoke()

    assert.isUndefined(ctx.response.getHeader('set-cookie'))
  })

  test('ignore a refresh token passed in the query string', async ({ assert }) => {
    const { User, user, refreshTokenUserProvider } = await setupRefreshTokens()
    const refreshToken = await User.refreshTokens.create(user)
    const ctx = new HttpContextFactory().create()

    const guard = new JwtGuard(ctx, new JwtFakeUserProvider(), {
      secret: TEST_SECRET,
      refreshTokenUserProvider,
    })

    ctx.request.updateQs({ refreshToken: refreshToken.value!.release() })

    await assert.rejects(() => guard.generateWithRefreshToken(), 'Unauthorized access')
    assert.isNotNull(await User.refreshTokens.verify(refreshToken.value!))
  })

  test('ignore a refresh token in the body that is not a string', async ({ assert }) => {
    const { User, user, refreshTokenUserProvider } = await setupRefreshTokens()
    const refreshToken = await User.refreshTokens.create(user)
    const ctx = new HttpContextFactory().create()

    const guard = new JwtGuard(ctx, new JwtFakeUserProvider(), {
      secret: TEST_SECRET,
      refreshTokenUserProvider,
    })

    ctx.request.setInitialBody({ refreshToken: [refreshToken.value!.release()] })

    await assert.rejects(() => guard.generateWithRefreshToken(), 'Unauthorized access')
  })
})

test.group('Security | refresh token reuse and expiration', () => {
  test('a refresh token cannot be replayed', async ({ assert }) => {
    const { User, user, refreshTokenUserProvider } = await setupRefreshTokens()
    const createdToken = await User.refreshTokens.create(user)
    const refreshToken = createdToken.value!.release()

    const firstGuard = new JwtGuard(new HttpContextFactory().create(), new JwtFakeUserProvider(), {
      secret: TEST_SECRET,
      refreshTokenUserProvider,
    })
    assert.exists(await firstGuard.generateWithRefreshToken(refreshToken))

    const replayGuard = new JwtGuard(new HttpContextFactory().create(), new JwtFakeUserProvider(), {
      secret: TEST_SECRET,
      refreshTokenUserProvider,
    })
    await assert.rejects(
      () => replayGuard.generateWithRefreshToken(refreshToken),
      'Unauthorized access'
    )
    assert.isFalse(replayGuard.isAuthenticated)
    assert.isUndefined(replayGuard.user)
  })

  test('only one of two concurrent refreshes with the same token succeeds', async ({ assert }) => {
    const { User, user, refreshTokenUserProvider } = await setupRefreshTokens()
    const createdToken = await User.refreshTokens.create(user)
    const refreshToken = createdToken.value!.release()

    const guards = [1, 2].map(
      () =>
        new JwtGuard(new HttpContextFactory().create(), new JwtFakeUserProvider(), {
          secret: TEST_SECRET,
          refreshTokenUserProvider,
        })
    )

    const results = await Promise.allSettled(
      guards.map((guard) => guard.generateWithRefreshToken(refreshToken))
    )

    assert.lengthOf(
      results.filter((result) => result.status === 'fulfilled'),
      1
    )
    const loser = guards[results.findIndex((result) => result.status === 'rejected')]!
    assert.isFalse(loser.isAuthenticated)
    assert.isUndefined(loser.user)
  })

  test('an expired refresh token is rejected', async ({ assert }) => {
    const { user, refreshTokenUserProvider } = await setupRefreshTokens()
    const options = {
      secret: TEST_SECRET,
      refreshTokenExpiresIn: '1h' as const,
      refreshTokenUserProvider,
    }

    const guard = new JwtGuard(
      new HttpContextFactory().create(),
      new JwtFakeUserProvider(),
      options
    )
    const { refreshToken } = await guard.generate(user)

    timeTravel(2 * 60 * 60)

    const refreshGuard = new JwtGuard(
      new HttpContextFactory().create(),
      new JwtFakeUserProvider(),
      options
    )
    await assert.rejects(
      () => refreshGuard.generateWithRefreshToken(refreshToken),
      'Unauthorized access'
    )
    assert.isFalse(refreshGuard.isAuthenticated)
    assert.isUndefined(refreshGuard.user)
  })
})

test.group('Security | failed refreshes leave the guard unauthenticated', () => {
  test('when {case}')
    .with([
      { case: 'no refresh token is sent' },
      { case: 'the refresh token is unknown' },
      { case: 'the user of the refresh token does not exist' },
      { case: 'the refresh token cannot be deleted' },
    ])
    .run(async ({ assert }, row) => {
      const { User, user, refreshTokenUserProvider } = await setupRefreshTokens()
      const createdToken = await User.refreshTokens.create(user)
      let refreshToken: string | undefined = createdToken.value!.release()

      if (row.case === 'no refresh token is sent') {
        refreshToken = undefined
      } else if (row.case === 'the refresh token is unknown') {
        refreshToken = 'rt_MTIz.unknown'
      } else if (row.case === 'the user of the refresh token does not exist') {
        await user.delete()
      } else {
        refreshTokenUserProvider.invalidateToken = async () => false
      }

      const guard = new JwtGuard(new HttpContextFactory().create(), new JwtFakeUserProvider(), {
        secret: TEST_SECRET,
        refreshTokenUserProvider,
      })

      await assert.rejects(
        () => guard.generateWithRefreshToken(refreshToken),
        'Unauthorized access'
      )
      assert.isTrue(guard.authenticationAttempted)
      assert.isFalse(guard.isAuthenticated)
      assert.isUndefined(guard.user)
    })
})

test.group('Security | Set-Cookie on generate', () => {
  test('access and refresh token cookies carry Max-Age, HttpOnly, Secure and SameSite', async ({
    assert,
  }) => {
    const { user, refreshTokenUserProvider } = await setupRefreshTokens()
    const ctx = new HttpContextFactory().create()

    const guard = new JwtGuard(ctx, new JwtFakeUserProvider(), {
      secret: TEST_SECRET,
      useCookies: true,
      useCookiesForRefreshToken: true,
      tokenExpiresIn: '15m',
      refreshTokenExpiresIn: '7d',
      cookie: { sameSite: 'strict' },
      refreshTokenUserProvider,
    })
    await guard.generate(user)

    const setCookie = ctx.response.getHeader('set-cookie') as string[]
    const tokenCookie = setCookie.find((cookie) => cookie.startsWith('token='))!
    const refreshCookie = setCookie.find((cookie) => cookie.startsWith('refreshToken='))!

    for (const cookie of [tokenCookie, refreshCookie]) {
      assert.include(cookie, 'HttpOnly')
      assert.include(cookie, 'Secure')
      assert.include(cookie, 'SameSite=Strict')
    }
    assert.include(tokenCookie, 'Max-Age=900')
    assert.include(refreshCookie, 'Max-Age=604800')
  })

  test('cookies are HttpOnly and Secure when no cookie options are set', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const userProvider = new JwtFakeUserProvider()

    const guard = new JwtGuard(ctx, userProvider, { secret: TEST_SECRET, useCookies: true })
    const user = await userProvider.findById(1)
    await guard.generate(user!.getOriginal())

    const tokenCookie = String(ctx.response.getHeader('set-cookie'))
    assert.match(tokenCookie, /^token=/)
    assert.include(tokenCookie, 'HttpOnly')
    assert.include(tokenCookie, 'Secure')
    assert.include(tokenCookie, 'Max-Age=3600')
  })
})

function base64url(value: Record<string, any>) {
  return Buffer.from(JSON.stringify(value)).toString('base64url')
}

function asymmetricGuardOptions(algorithm: 'RS256' | 'ES256') {
  const { publicKey, privateKey } =
    algorithm === 'RS256'
      ? crypto.generateKeyPairSync('rsa', {
          modulusLength: 2048,
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        })
      : crypto.generateKeyPairSync('ec', {
          namedCurve: 'P-256',
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        })

  return { privateKey, publicKey, algorithm }
}

async function authenticateWith(options: Record<string, any>, token: string) {
  const ctx = new HttpContextFactory().create()
  const guard = new JwtGuard(ctx, new JwtFakeUserProvider(), options)
  ctx.request.request.headers.authorization = `Bearer ${token}`
  await guard.authenticate()
  return guard
}

test.group('Security | forged tokens', () => {
  const now = () => Math.floor(Date.now() / 1000)

  test('reject an unsigned token (alg: none) with the {mode} driver')
    .with([{ mode: 'symmetric' }, { mode: 'asymmetric' }])
    .run(async ({ assert }, row) => {
      const options =
        row.mode === 'symmetric' ? { secret: TEST_SECRET } : asymmetricGuardOptions('RS256')
      const token = `${base64url({ alg: 'none', typ: 'JWT' })}.${base64url({ userId: 1, exp: now() + 60 })}.`

      await assert.rejects(() => authenticateWith(options, token), 'Unauthorized access')
    })

  test('reject a HS256 token signed with the {algorithm} public key')
    .with([{ algorithm: 'RS256' as const }, { algorithm: 'ES256' as const }])
    .run(async ({ assert }, row) => {
      const options = asymmetricGuardOptions(row.algorithm)
      const unsigned = `${base64url({ alg: 'HS256', typ: 'JWT' })}.${base64url({ userId: 1, exp: now() + 60 })}`
      const signature = crypto
        .createHmac('sha256', options.publicKey)
        .update(unsigned)
        .digest('base64url')

      await assert.rejects(
        () => authenticateWith(options, `${unsigned}.${signature}`),
        'Unauthorized access'
      )
    })

  test('reject a token with a {tampering} ({mode} driver)')
    .with([
      { tampering: 'modified payload', mode: 'symmetric' },
      { tampering: 'truncated signature', mode: 'symmetric' },
      { tampering: 'modified payload', mode: 'asymmetric' },
      { tampering: 'truncated signature', mode: 'asymmetric' },
    ])
    .run(async ({ assert }, row) => {
      const options =
        row.mode === 'symmetric' ? { secret: TEST_SECRET } : asymmetricGuardOptions('RS256')
      const userProvider = new JwtFakeUserProvider()
      const guard = new JwtGuard(new HttpContextFactory().create(), userProvider, options)
      const user = await userProvider.findById(1)
      const { token } = await guard.generate(user!.getOriginal())

      /**
       * Control: the untouched token is accepted
       */
      const controlGuard = await authenticateWith(options, token)
      assert.isTrue(controlGuard.isAuthenticated)

      const [header, payload, signature] = token.split('.')
      const forged =
        row.tampering === 'modified payload'
          ? `${header}.${base64url({ ...JSON.parse(Buffer.from(payload!, 'base64url').toString()), userId: 2 })}.${signature}`
          : `${header}.${payload}.${signature!.slice(0, -4)}`

      await assert.rejects(() => authenticateWith(options, forged), 'Unauthorized access')
    })
})

test.group('Security | clockTolerance', () => {
  test('{mode} driver: a token expired 30s ago is {expected} with clockTolerance {clockTolerance}')
    .with([
      { mode: 'symmetric', clockTolerance: 60, expected: 'accepted' },
      { mode: 'symmetric', clockTolerance: 10, expected: 'rejected' },
      { mode: 'symmetric', clockTolerance: undefined, expected: 'rejected' },
      { mode: 'asymmetric', clockTolerance: 60, expected: 'accepted' },
      { mode: 'asymmetric', clockTolerance: 10, expected: 'rejected' },
      { mode: 'asymmetric', clockTolerance: undefined, expected: 'rejected' },
    ])
    .run(async ({ assert }, row) => {
      const keys =
        row.mode === 'symmetric' ? { secret: TEST_SECRET } : asymmetricGuardOptions('RS256')
      const userProvider = new JwtFakeUserProvider()
      const issuer = new JwtGuard(new HttpContextFactory().create(), userProvider, {
        ...keys,
        tokenExpiresIn: 60,
      })
      const user = await userProvider.findById(1)
      const { token } = await issuer.generate(user!.getOriginal())

      timeTravel(90)

      const options = { ...keys, clockTolerance: row.clockTolerance }
      if (row.expected === 'accepted') {
        const controlGuard = await authenticateWith(options, token)
        assert.isTrue(controlGuard.isAuthenticated)
      } else {
        await assert.rejects(() => authenticateWith(options, token), 'Unauthorized access')
      }
    })
})
