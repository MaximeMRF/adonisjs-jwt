import { test } from '@japa/runner'
import { JwtGuard } from '../src/guard.js'
import { JwksDriver } from '../src/drivers/jwks.js'
import { jwtGuard } from '../src/define_config.js'
import { HttpContextFactory } from '@adonisjs/core/factories/http'
import { Redirect } from '@adonisjs/core/http'
import { JwtFakeUserProvider } from '../factories/main.js'
import { BaseModel, column } from '@adonisjs/lucid/orm'
import { AuthManager, errors } from '@adonisjs/auth'
import { installJwtUnauthorizedRenderer } from '../src/errors.js'
import { DbAccessTokensProvider, tokensUserProvider } from '@adonisjs/auth/access_tokens'
import { createDatabase, createTables, signCookie, timeTravel, TEST_SECRET } from './helpers.js'
import { Secret } from '@adonisjs/core/helpers'
import { RuntimeException } from '@adonisjs/core/exceptions'
import jwt from 'jsonwebtoken'
import nock from 'nock'
import crypto from 'node:crypto'

const APP_KEY = 'app-key-with-at-least-32-characters'

/**
 * `app.appKey` is a Secret in AdonisJS v6 apps (`new Secret(env.get('APP_KEY'))`),
 * or a plain string when it was added by hand to a v7 app for 0.9
 */
function fakeApp(appKey?: string, { asString = false } = {}) {
  return {
    config: {
      get: () => (appKey === undefined ? undefined : asString ? appKey : { release: () => appKey }),
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

    assert.equal(result.expiresIn, 3600)
    assert.equal(payload.exp! - payload.iat!, 60 * 60)
  })

  test('throw when tokenExpiresIn is {value}')
    .with([{ value: 0 }, { value: -60 }, { value: Number.NaN }])
    .run(({ assert }, { value }) => {
      const ctx = new HttpContextFactory().create()
      const userProvider = new JwtFakeUserProvider()

      assert.throws(
        () => new JwtGuard(ctx, userProvider, { secret: TEST_SECRET, tokenExpiresIn: value }),
        'JWT guard `tokenExpiresIn` must be a positive number of seconds'
      )
    })

  test('throw at startup when tokenExpiresIn is not positive', ({ assert }) => {
    assert.throws(
      () =>
        jwtGuard({
          provider: new JwtFakeUserProvider(),
          secret: TEST_SECRET,
          tokenExpiresIn: 0,
        }),
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
    .run(async ({ assert, cleanup }, { appKey }) => {
      const previous = process.env.APP_KEY
      delete process.env.APP_KEY
      cleanup(() => {
        if (previous !== undefined) process.env.APP_KEY = previous
      })

      await assert.rejects(
        () => jwtGuard({ provider: new JwtFakeUserProvider() }).resolver('jwt', fakeApp(appKey)),
        'JWT guard requires the application key (APP_KEY) to be at least 32 characters when no `secret` is configured'
      )
    })

  test('read APP_KEY from the environment when config/app.ts has no appKey (AdonisJS v7)', async ({
    assert,
    cleanup,
  }) => {
    const previous = process.env.APP_KEY
    process.env.APP_KEY = APP_KEY
    cleanup(() => {
      if (previous === undefined) delete process.env.APP_KEY
      else process.env.APP_KEY = previous
    })

    const userProvider = new JwtFakeUserProvider()
    const user = await userProvider.findById(1)

    const v7Factory = await jwtGuard({ provider: userProvider }).resolver('jwt', fakeApp())
    const { token } = await v7Factory(new HttpContextFactory().create()).generate(
      user!.getOriginal()
    )

    // Same derived key as with app.appKey: tokens stay valid when moving to v7
    const v6Factory = await jwtGuard({ provider: userProvider }).resolver('jwt', fakeApp(APP_KEY))
    const ctx = new HttpContextFactory().create()
    ctx.request.request.headers.authorization = `Bearer ${token}`
    assert.isTrue(await v6Factory(ctx).check())
  })

  test('accept a plain string app.appKey, as added by hand to config/app.ts for 0.9', async ({
    assert,
  }) => {
    const userProvider = new JwtFakeUserProvider()
    const user = await userProvider.findById(1)

    const stringFactory = await jwtGuard({ provider: userProvider }).resolver(
      'jwt',
      fakeApp(APP_KEY, { asString: true })
    )
    const { token } = await stringFactory(new HttpContextFactory().create()).generate(
      user!.getOriginal()
    )

    // Same derived key as with a Secret: removing the line from config/app.ts keeps tokens valid
    const secretFactory = await jwtGuard({ provider: userProvider }).resolver(
      'jwt',
      fakeApp(APP_KEY)
    )
    const ctx = new HttpContextFactory().create()
    ctx.request.request.headers.authorization = `Bearer ${token}`
    assert.isTrue(await secretFactory(ctx).check())
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
      {
        // e.g. an audience list read from an env variable with a trailing comma
        missing: 'an empty string in the audience',
        options: { issuer: 'jwks-issuer', audience: ['jwks-audience', ''] },
      },
    ])
    .run(({ assert }, { options }) => {
      assert.throws(
        () =>
          jwtGuard({
            provider: new JwtFakeUserProvider(),
            jwks: { jwksUri },
            ...options,
          }),
        /JWT guard JWKS validation failed: `issuer` and either `audience` or `verifyPayload` are required/
      )
    })

  test('accept verifyPayload instead of audience in JWKS mode', async ({ assert }) => {
    const resolver = await jwtGuard({
      provider: new JwtFakeUserProvider(),
      jwks: { jwksUri },
      issuer: 'jwks-issuer',
      verifyPayload: (payload) => payload.client_id === 'my-client',
    }).resolver('jwt', fakeApp())

    assert.isFunction(resolver)
  })

  test('still require issuer when verifyPayload is set', ({ assert }) => {
    assert.throws(
      () =>
        jwtGuard({
          provider: new JwtFakeUserProvider(),
          jwks: { jwksUri },
          verifyPayload: () => true,
        }),
      /`issuer` and either `audience` or `verifyPayload` are required/
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
        expiresIn: '1h',
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
  test('revoke clears the cookies even when no refresh token is sent', async ({ assert }) => {
    const { refreshTokenUserProvider } = await setupRefreshTokens()
    const ctx = new HttpContextFactory().create()

    const guard = new JwtGuard(ctx, new JwtFakeUserProvider(), {
      secret: TEST_SECRET,
      useCookies: true,
      useCookiesForRefreshToken: true,
      refreshTokenUserProvider,
    })

    ctx.request.request.headers.accept = 'application/json'
    const error = await guard.revoke().catch((e) => e)
    assert.instanceOf(error, errors.E_UNAUTHORIZED_ACCESS)
    // the 401 rendered by the exception handler keeps the cookies cleared
    await error.handle(error, ctx)
    assert.equal(ctx.response.getStatus(), 401)

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

    await assert.rejects(() => guard.revoke(), errors.E_UNAUTHORIZED_ACCESS)

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

test.group('Security | revoke with a forged refresh token', () => {
  test('revoke rejects a refresh token with a valid id and a wrong secret', async ({ assert }) => {
    const { User, user, refreshTokenUserProvider } = await setupRefreshTokens()
    const created = await User.refreshTokens.create(user)
    const forged = `rt_${Buffer.from(String(created.identifier)).toString('base64url')}.${Buffer.from('forged-secret').toString('base64url')}`

    const ctx = new HttpContextFactory().create()
    ctx.request.setInitialBody({ refreshToken: forged })
    const attacker = new JwtGuard(ctx, new JwtFakeUserProvider(), {
      secret: TEST_SECRET,
      refreshTokenUserProvider,
    })
    await assert.rejects(() => attacker.revoke(), errors.E_UNAUTHORIZED_ACCESS)

    assert.isNotNull(await User.refreshTokens.verify(created.value!))
    const victim = new JwtGuard(new HttpContextFactory().create(), new JwtFakeUserProvider(), {
      secret: TEST_SECRET,
      refreshTokenUserProvider,
    })
    assert.exists(await victim.generateWithRefreshToken(created.value!.release()))
  })

  test('revoke still deletes a valid refresh token', async ({ assert }) => {
    const { User, user, refreshTokenUserProvider } = await setupRefreshTokens()
    const created = await User.refreshTokens.create(user)

    const guard = new JwtGuard(new HttpContextFactory().create(), new JwtFakeUserProvider(), {
      secret: TEST_SECRET,
      refreshTokenUserProvider,
    })
    await guard.revoke(created.value!.release())

    assert.isNull(await User.refreshTokens.verify(created.value!))
  })
})

test.group('Security | verifyPayload accepts only true', () => {
  async function authenticateWithVerifyPayload(
    verifyPayload: (payload: Record<string, any>) => any
  ) {
    const userProvider = new JwtFakeUserProvider()
    const signer = new JwtGuard(new HttpContextFactory().create(), userProvider, {
      secret: TEST_SECRET,
    })
    const { token } = await signer.generate((await userProvider.findById(1))!.getOriginal())

    const ctx = new HttpContextFactory().create()
    ctx.request.request.headers.authorization = `Bearer ${token}`
    return new JwtGuard(ctx, userProvider, { secret: TEST_SECRET, verifyPayload }).authenticate()
  }

  test('reject the token when verifyPayload returns {case}')
    .with([
      { case: 'a non-empty string', verifyPayload: () => 'wrong client' },
      { case: 'a claim value', verifyPayload: (p: Record<string, any>) => p.userId },
      { case: 'an object', verifyPayload: () => ({}) },
      { case: 'undefined', verifyPayload: () => undefined },
      { case: 'a promise resolving to false', verifyPayload: async () => false },
      { case: 'a promise resolving to a string', verifyPayload: async () => 'yes' },
    ])
    .run(async ({ assert }, { verifyPayload }) => {
      await assert.rejects(
        () => authenticateWithVerifyPayload(verifyPayload),
        'Unauthorized access'
      )
    })

  test('reject the token with a 401 when verifyPayload throws', async ({ assert }) => {
    // E_UNAUTHORIZED_ACCESS is a 401, the TypeError raised by verifyPayload would be a 500
    await assert.rejects(
      () => authenticateWithVerifyPayload((p) => p.missing.claim === 'x'),
      errors.E_UNAUTHORIZED_ACCESS
    )
  })

  test('accept the token when verifyPayload resolves to true', async ({ assert }) => {
    const user = await authenticateWithVerifyPayload(async () => true)
    assert.equal(user.id, 1)
  })
})

test.group('Security | the configuration is validated at startup', (group) => {
  let previousAppKey: string | undefined
  group.each.setup(() => {
    previousAppKey = process.env.APP_KEY
    delete process.env.APP_KEY
  })
  group.each.teardown(() => {
    if (previousAppKey === undefined) delete process.env.APP_KEY
    else process.env.APP_KEY = previousAppKey
  })

  test('throw when jwtGuard() is called with {case}')
    .with([
      { case: "tokenExpiresIn: '-1h'", options: { tokenExpiresIn: '-1h' } },
      { case: "tokenExpiresIn: 'abc'", options: { tokenExpiresIn: 'abc' } },
      { case: "tokenExpiresIn: '0s'", options: { tokenExpiresIn: '0s' } },
      { case: "tokenExpiresIn: '999ms'", options: { tokenExpiresIn: '999ms' } },
      { case: 'tokenExpiresIn: Infinity', options: { tokenExpiresIn: Number.POSITIVE_INFINITY } },
      { case: 'tokenExpiresIn: true', options: { tokenExpiresIn: true } },
      {
        case: "refreshTokenExpiresIn: '604800' (no unit)",
        options: { refreshTokenExpiresIn: '604800' },
      },
      { case: "tokenExpiresIn: '3600' (no unit)", options: { tokenExpiresIn: '3600' } },
      { case: 'tokenExpiresIn: -60', options: { tokenExpiresIn: -60 } },
      { case: "refreshTokenExpiresIn: '-7d'", options: { refreshTokenExpiresIn: '-7d' } },
      { case: 'refreshTokenExpiresIn: 0', options: { refreshTokenExpiresIn: 0 } },
      { case: 'clockTolerance: -30', options: { clockTolerance: -30 } },
      { case: 'clockTolerance: NaN', options: { clockTolerance: Number.NaN } },
    ])
    .run(({ assert }, { options }) => {
      assert.throws(
        () =>
          jwtGuard({
            provider: new JwtFakeUserProvider(),
            secret: TEST_SECRET,
            ...(options as any),
          }),
        /^JWT guard `(tokenExpiresIn|refreshTokenExpiresIn|clockTolerance)`/
      )
    })

  test('accept {case}')
    .with([
      { case: "tokenExpiresIn: '1s' (the minimum)", options: { tokenExpiresIn: '1s' } },
      { case: "tokenExpiresIn: '15m'", options: { tokenExpiresIn: '15m' } },
      { case: "tokenExpiresIn: '1.5h'", options: { tokenExpiresIn: '1.5h' } },
      { case: 'tokenExpiresIn: 900', options: { tokenExpiresIn: 900 } },
      { case: "refreshTokenExpiresIn: '7d'", options: { refreshTokenExpiresIn: '7d' } },
      { case: 'clockTolerance: 0', options: { clockTolerance: 0 } },
    ])
    .run(({ assert }, { options }) => {
      assert.doesNotThrow(() =>
        jwtGuard({ provider: new JwtFakeUserProvider(), secret: TEST_SECRET, ...(options as any) })
      )
    })

  test('throw when the secret is shorter than 32 characters', ({ assert }) => {
    assert.throws(
      () => jwtGuard({ provider: new JwtFakeUserProvider(), secret: 'my-short-secret' }),
      /at least 32 characters/
    )
  })

  test('throw when APP_KEY is shorter than 32 characters and no secret is configured', ({
    assert,
  }) => {
    process.env.APP_KEY = 'short-app-key'
    assert.throws(
      () => jwtGuard({ provider: new JwtFakeUserProvider() }),
      'JWT guard requires the application key (APP_KEY) to be at least 32 characters when no `secret` is configured'
    )
  })

  test('throw when JWKS is used with {case}')
    .with([
      { case: 'no jwksUri', jwks: {} },
      { case: 'an empty jwksUri', jwks: { jwksUri: '' } },
      { case: 'a blank jwksUri', jwks: { jwksUri: '   ' } },
    ])
    .run(({ assert }, { jwks }) => {
      assert.throws(
        () =>
          jwtGuard({
            provider: new JwtFakeUserProvider(),
            jwks: jwks as any,
            issuer: 'jwks-issuer',
            audience: 'jwks-audience',
          }),
        'JWT guard `jwks.jwksUri` is required to fetch the identity provider keys'
      )
    })

  test('a guard created without jwtGuard() validates the lifetimes too', ({ assert }) => {
    assert.throws(
      () =>
        new JwtGuard(new HttpContextFactory().create(), new JwtFakeUserProvider(), {
          secret: TEST_SECRET,
          tokenExpiresIn: '-1h',
        }),
      /^JWT guard `tokenExpiresIn` must be a duration of at least 1 second/
    )
  })

  test('throw when the {algorithm} public key belongs to another key pair')
    .with([{ algorithm: 'RS256' as const }, { algorithm: 'ES256' as const }])
    .run(({ assert }, { algorithm }) => {
      const { privateKey } = asymmetricGuardOptions(algorithm)
      const { publicKey } = asymmetricGuardOptions(algorithm)

      assert.throws(
        () => jwtGuard({ provider: new JwtFakeUserProvider(), privateKey, publicKey, algorithm }),
        'JWT guard asymmetric key validation failed: publicKey does not belong to the same key pair as privateKey'
      )
    })

  test('accept a matching {algorithm} key pair')
    .with([{ algorithm: 'RS256' as const }, { algorithm: 'ES256' as const }])
    .run(({ assert }, { algorithm }) => {
      const keys = asymmetricGuardOptions(algorithm)
      assert.doesNotThrow(() => jwtGuard({ provider: new JwtFakeUserProvider(), ...keys }))
    })
})

test.group('Security | 401 responses', () => {
  async function render(accept: string, options: { redirectTo?: string } = {}) {
    const ctx = new HttpContextFactory().create()
    ctx.request.request.headers.accept = accept
    const error = new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: 'jwt',
      ...options,
    })
    await error.handle(error, ctx)
    return ctx.response
  }

  test('JSON requests get a JSON body, like the access_tokens guard', async ({ assert }) => {
    const response = await render('application/json')

    assert.equal(response.getStatus(), 401)
    assert.deepEqual(response.getBody(), { errors: [{ message: 'Unauthorized access' }] })
  })

  test('JSON:API requests get a JSON:API body', async ({ assert }) => {
    const response = await render('application/vnd.api+json')

    assert.equal(response.getStatus(), 401)
    assert.deepEqual(response.getBody(), {
      errors: [{ code: 'E_UNAUTHORIZED_ACCESS', title: 'Unauthorized access' }],
    })
  })

  test('without a login route, a client sending Accept: {accept} gets a 401, not a redirect')
    .with([{ accept: '*/*' }, { accept: 'text/html' }])
    .run(async ({ assert }, { accept }) => {
      // curl and most HTTP clients send */*, which negotiates as HTML
      const response = await render(accept)

      assert.equal(response.getStatus(), 401)
      assert.equal(response.getBody(), 'Unauthorized access')
      assert.isUndefined(response.getHeader('location'))
    })

  test('HTML requests (pages, Inertia visits) are redirected to the login route', async ({
    assert,
  }) => {
    const response = await render('text/html, application/xhtml+xml', { redirectTo: '/login' })

    assert.equal(response.getStatus(), 302)
    assert.equal(response.getHeader('location'), '/login')
  })

  test('with @adonisjs/session, the redirect keeps the intended URL, like the session guard', async ({
    assert,
    cleanup,
  }) => {
    // @adonisjs/session adds this macro, so the user goes back to the page after logging in
    let intendedUrlSaved = 0
    Redirect.macro('withIntendedUrl' as any, function (this: Redirect) {
      intendedUrlSaved++
      return this
    })
    cleanup(() => {
      delete (Redirect.prototype as { withIntendedUrl?: unknown }).withIntendedUrl
    })

    const response = await render('text/html', { redirectTo: '/login' })

    assert.equal(intendedUrlSaved, 1)
    assert.equal(response.getStatus(), 302)
    assert.equal(response.getHeader('location'), '/login')
  })

  test('JSON requests are not redirected even when there is a login route', async ({ assert }) => {
    const response = await render('application/json', { redirectTo: '/login' })

    assert.equal(response.getStatus(), 401)
    assert.deepEqual(response.getBody(), { errors: [{ message: 'Unauthorized access' }] })
  })

  async function authenticateThroughMiddleware(accept: string, loginRoute?: string) {
    const ctx = new HttpContextFactory().create()
    ctx.request.request.headers.accept = accept
    const manager = new AuthManager({
      default: 'jwt',
      guards: {
        jwt: (c) => new JwtGuard(c, new JwtFakeUserProvider(), { secret: TEST_SECRET }),
      },
    })

    // what the starter kits' auth middleware does
    const error = await manager
      .createAuthenticator(ctx)
      .authenticateUsing(['jwt'], loginRoute ? { loginRoute } : undefined)
      .catch((e) => e)
    if (!(error instanceof errors.E_UNAUTHORIZED_ACCESS)) {
      throw new Error('authenticateUsing should have raised E_UNAUTHORIZED_ACCESS')
    }
    await error.handle(error, ctx)
    return ctx.response
  }

  test('auth middleware with a login route (Inertia kit): a page visit is redirected', async ({
    assert,
  }) => {
    const response = await authenticateThroughMiddleware(
      'text/html, application/xhtml+xml',
      '/login'
    )

    assert.equal(response.getStatus(), 302)
    assert.equal(response.getHeader('location'), '/login')
  })

  test('auth middleware with a login route: a fetch() from the same app still gets JSON', async ({
    assert,
  }) => {
    const response = await authenticateThroughMiddleware('application/json', '/login')

    assert.equal(response.getStatus(), 401)
    assert.deepEqual(response.getBody(), { errors: [{ message: 'Unauthorized access' }] })
  })

  test('auth middleware without a login route (API kit): JSON 401', async ({ assert }) => {
    const response = await authenticateThroughMiddleware('application/json')

    assert.equal(response.getStatus(), 401)
    assert.deepEqual(response.getBody(), { errors: [{ message: 'Unauthorized access' }] })
  })

  test('installing the renderer twice does not wrap the handler twice', ({ assert }) => {
    const handle = errors.E_UNAUTHORIZED_ACCESS.prototype.handle
    installJwtUnauthorizedRenderer()
    assert.strictEqual(errors.E_UNAUTHORIZED_ACCESS.prototype.handle, handle)
  })

  test('a 401 raised by the guard is rendered as JSON', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    ctx.request.request.headers.accept = 'application/json'
    ctx.request.request.headers.authorization = 'Bearer not-a-jwt'
    const guard = new JwtGuard(ctx, new JwtFakeUserProvider(), { secret: TEST_SECRET })

    const error = await guard.authenticate().catch((e) => e)
    assert.instanceOf(error, errors.E_UNAUTHORIZED_ACCESS)
    await error.handle(error, ctx)

    assert.equal(ctx.response.getStatus(), 401)
    assert.deepEqual(ctx.response.getBody(), { errors: [{ message: 'Unauthorized access' }] })
  })

  test('a jwt renderer registered by the application takes precedence', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    ctx.request.request.headers.accept = 'application/json'
    const error = new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: 'jwt',
    })
    ;(error.renderers as Record<string, any>).jwt = (_: string, __: unknown, c: any) =>
      c.response.status(401).send({ custom: true })

    await error.handle(error, ctx)

    assert.deepEqual(ctx.response.getBody(), { custom: true })
  })

  test('the other guards keep their own renderers', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    ctx.request.request.headers.accept = 'text/html'
    const error = new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: 'basic_auth',
    })

    await error.handle(error, ctx)

    assert.match(ctx.response.getHeader('www-authenticate') as string, /^Basic realm/)
  })
})

test.group('Security | revoke only succeeds when a refresh token is revoked', () => {
  test('a bearer client that sends its access token on logout gets a 401', async ({ assert }) => {
    const { User, user, refreshTokenUserProvider } = await setupRefreshTokens()
    const options = { secret: TEST_SECRET, refreshTokenUserProvider }
    const { token, refreshToken } = await new JwtGuard(
      new HttpContextFactory().create(),
      new JwtFakeUserProvider(),
      options
    ).generate(user)

    const ctx = new HttpContextFactory().create()
    ctx.request.request.headers.authorization = `Bearer ${token}`
    const guard = new JwtGuard(ctx, new JwtFakeUserProvider(), options)

    await assert.rejects(() => guard.revoke(), errors.E_UNAUTHORIZED_ACCESS)
    // the refresh token was not revoked, and the client now knows it
    assert.isNotNull(await User.refreshTokens.verify(new Secret(refreshToken!)))
  })

  test('revoking the same refresh token twice fails the second time', async ({ assert }) => {
    const { User, user, refreshTokenUserProvider } = await setupRefreshTokens()
    const created = await User.refreshTokens.create(user)
    const refreshToken = created.value!.release()
    const newGuard = () =>
      new JwtGuard(new HttpContextFactory().create(), new JwtFakeUserProvider(), {
        secret: TEST_SECRET,
        refreshTokenUserProvider,
      })

    await newGuard().revoke(refreshToken)
    await assert.rejects(() => newGuard().revoke(refreshToken), errors.E_UNAUTHORIZED_ACCESS)
  })

  test('after a refresh in the same request, revoke the refresh token it issued', async ({
    assert,
  }) => {
    const { User, user, refreshTokenUserProvider } = await setupRefreshTokens()
    const created = await User.refreshTokens.create(user)
    const oldRefreshToken = created.value!.release()

    const ctx = new HttpContextFactory().create()
    ctx.request.request.headers.cookie = `refreshToken=${signCookie('refreshToken', oldRefreshToken)}`
    const guard = new JwtGuard(ctx, new JwtFakeUserProvider(), {
      secret: TEST_SECRET,
      useCookies: true,
      useCookiesForRefreshToken: true,
      refreshTokenUserProvider,
    })

    // e.g. a middleware refreshes the expired access token, then the route logs out
    const { refreshToken: newRefreshToken } = await guard.generateWithRefreshToken()
    await guard.revoke()

    assert.isNull(await User.refreshTokens.verify(new Secret(oldRefreshToken)))
    assert.isNull(await User.refreshTokens.verify(new Secret(newRefreshToken)))
  })
})

test.group('Security | tokens without exp are rejected', (group) => {
  group.each.teardown(() => {
    nock.cleanAll()
  })

  test('symmetric driver: a validly signed token without exp is rejected', async ({ assert }) => {
    // NO_EXP: e.g. issued by another service that shares the secret
    const token = jwt.sign({ userId: 1, iat: 1 }, TEST_SECRET)

    await assert.rejects(
      () => authenticateWith({ secret: TEST_SECRET }, token),
      errors.E_UNAUTHORIZED_ACCESS
    )
  })

  test('{algorithm}: a validly signed token without exp is rejected')
    .with([{ algorithm: 'RS256' as const }, { algorithm: 'ES256' as const }])
    .run(async ({ assert }, { algorithm }) => {
      const options = asymmetricGuardOptions(algorithm)
      // NO_EXP
      const token = jwt.sign({ userId: 1 }, options.privateKey, { algorithm })

      await assert.rejects(() => authenticateWith(options, token), errors.E_UNAUTHORIZED_ACCESS)
    })

  test('JWKS: a token without exp from the identity provider is rejected', async ({ assert }) => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    })
    const jwk = { ...crypto.createPublicKey(publicKey).export({ format: 'jwk' }), kid: 'k1' }
    nock('https://no-exp.example.com')
      .persist()
      .get('/.well-known/jwks.json')
      .reply(200, { keys: [jwk] })

    const claims = { issuer: 'idp', audience: 'api' }
    const driver = new JwksDriver(
      { jwksUri: 'https://no-exp.example.com/.well-known/jwks.json' },
      claims
    )
    const sign = (expiresIn?: '1h') =>
      // NO_EXP when expiresIn is undefined
      jwt.sign({ userId: 1 }, privateKey, {
        algorithm: 'RS256',
        keyid: 'k1',
        ...claims,
        ...(expiresIn ? { expiresIn } : {}),
      })

    // the same token with exp is accepted: the rejection comes from the missing exp
    const guard = await authenticateWith({ driver }, sign('1h'))
    assert.equal(guard.user!.id, 1)
    await assert.rejects(() => authenticateWith({ driver }, sign()), errors.E_UNAUTHORIZED_ACCESS)
  })
})

test.group('Security | verifyPayload must be a function', () => {
  test('throw at startup when verifyPayload is {value}')
    .with([{ value: null }, { value: false }, { value: 'client_id' }])
    .run(({ assert }, { value }) => {
      // with JWKS, a falsy verifyPayload used to replace the required audience
      assert.throws(
        () =>
          jwtGuard({
            provider: new JwtFakeUserProvider(),
            jwks: { jwksUri: 'https://idp.example.com/.well-known/jwks.json' },
            issuer: 'idp',
            verifyPayload: value as any,
          }),
        'JWT guard `verifyPayload` must be a function'
      )
    })
})

test.group('Security | the app key mode validates the options at startup', (group) => {
  let previousAppKey: string | undefined
  group.each.setup(() => {
    previousAppKey = process.env.APP_KEY
  })
  group.each.teardown(() => {
    if (previousAppKey === undefined) delete process.env.APP_KEY
    else process.env.APP_KEY = previousAppKey
  })

  // Without `secret`, the default config of `node ace configure`: these
  // options used to boot fine, then every token was rejected without an error
  test('throw at startup without secret when {case} ({env})')
    .with(
      [
        {
          case: "verifyPayload: 'yes'",
          options: { verifyPayload: 'yes' },
          error: '`verifyPayload` must be a function',
        },
        {
          case: 'verifyPayload: null',
          options: { verifyPayload: null },
          error: '`verifyPayload` must be a function',
        },
        {
          case: 'audience: []',
          options: { audience: [] },
          error: '`audience` must be a non-empty string',
        },
        {
          case: "issuer: ''",
          options: { issuer: '' },
          error: '`issuer` must be a non-empty string',
        },
      ].flatMap((item) => [
        { ...item, env: 'APP_KEY set', appKey: APP_KEY },
        { ...item, env: 'APP_KEY not loaded yet', appKey: undefined },
      ])
    )
    .run(({ assert }, { options, error, appKey }) => {
      if (appKey === undefined) delete process.env.APP_KEY
      else process.env.APP_KEY = appKey

      assert.throws(
        () => jwtGuard({ provider: new JwtFakeUserProvider(), ...(options as any) }),
        new RegExp(`^JWT guard ${error.replace(/[`[\]]/g, '\\$&')}`)
      )
    })

  test('a valid config without secret still boots and issues tokens', async ({ assert }) => {
    process.env.APP_KEY = APP_KEY
    const userProvider = new JwtFakeUserProvider()
    const user = await userProvider.findById(1)

    const factory = await jwtGuard({
      provider: userProvider,
      issuer: 'my-app',
      audience: 'my-api',
      verifyPayload: () => true,
    }).resolver('jwt', fakeApp())
    const { token } = await factory(new HttpContextFactory().create()).generate(user!.getOriginal())

    const ctx = new HttpContextFactory().create()
    ctx.request.request.headers.authorization = `Bearer ${token}`
    assert.isTrue(await factory(ctx).check())
  })
})

test.group('Security | content must not set the claims of the guard', () => {
  test('a content that sets {claim} gets a clear error, not the jsonwebtoken one')
    .with([
      { claim: 'exp', options: {}, content: { exp: 4102444800 }, option: 'tokenExpiresIn' },
      { claim: 'iss', options: { issuer: 'my-app' }, content: { iss: 'other' }, option: 'issuer' },
      {
        claim: 'aud',
        options: { audience: 'my-api' },
        content: { aud: 'other' },
        option: 'audience',
      },
    ])
    .run(async ({ assert }, { claim, options, content, option }) => {
      // e.g. a content written for 0.9, where tokens had no default lifetime
      const userProvider = new JwtFakeUserProvider()
      const user = await userProvider.findById(1)
      const guard = new JwtGuard(new HttpContextFactory().create(), userProvider, {
        secret: TEST_SECRET,
        ...options,
        content: (u) => ({ userId: u.getId(), ...content }) as any,
      })

      await assert.rejects(
        () => guard.generate(user!.getOriginal()),
        `JWT guard \`content\` must not set \`${claim}\`: the guard sets it from \`${option}\``
      )
    })

  test('content may set iss and aud when the guard does not', async ({ assert }) => {
    const userProvider = new JwtFakeUserProvider()
    const user = await userProvider.findById(1)
    const guard = new JwtGuard(new HttpContextFactory().create(), userProvider, {
      secret: TEST_SECRET,
      content: (u) => ({ userId: u.getId(), iss: 'my-app', aud: 'my-api' }),
    })

    const { token } = await guard.generate(user!.getOriginal())
    assert.include(jwt.decode(token) as object, { iss: 'my-app', aud: 'my-api' })
  })
})

test.group('Security | check() only hides authentication failures', () => {
  class DatabaseDownProvider extends JwtFakeUserProvider {
    async findById(): Promise<never> {
      throw new Error('database is down')
    }
  }

  test('a database outage is rethrown instead of looking like a guest', async ({ assert }) => {
    const token = jwt.sign({ userId: 1 }, TEST_SECRET, { expiresIn: '1h' })
    const ctx = new HttpContextFactory().create()
    ctx.request.request.headers.authorization = `Bearer ${token}`
    const guard = new JwtGuard(ctx, new DatabaseDownProvider(), { secret: TEST_SECRET })

    await assert.rejects(() => guard.check(), 'database is down')
  })

  test('an invalid token still makes check() return false', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    ctx.request.request.headers.authorization = 'Bearer not-a-jwt'
    const guard = new JwtGuard(ctx, new DatabaseDownProvider(), { secret: TEST_SECRET })

    assert.isFalse(await guard.check())
  })
})

test.group('Security | the user id taken from the token', () => {
  class SpyProvider extends JwtFakeUserProvider {
    ids: unknown[] = []
    async findById(id: any) {
      this.ids.push(id)
      return super.findById(Number(id))
    }
  }

  async function authenticateWithUserId(getUserId: (claims: Record<string, any>) => any) {
    const provider = new SpyProvider()
    const token = jwt.sign({ userId: 1, sub: '1' }, TEST_SECRET, { expiresIn: '1h' })
    const ctx = new HttpContextFactory().create()
    ctx.request.request.headers.authorization = `Bearer ${token}`
    const guard = new JwtGuard(ctx, provider, { secret: TEST_SECRET, getUserId })
    const result = await Promise.allSettled([guard.authenticate()])
    return { provider, result: result[0]! }
  }

  test('reject the token with a 401 when getUserId returns {case}')
    .with([
      { case: 'an object', getUserId: () => ({ id: 1 }) },
      { case: 'an array', getUserId: () => [1] },
      { case: 'an empty string', getUserId: () => '' },
      { case: 'NaN', getUserId: () => Number.NaN },
      { case: 'Infinity', getUserId: () => Number.POSITIVE_INFINITY },
      { case: 'a boolean', getUserId: () => true },
      { case: 'null', getUserId: () => null },
      { case: 'undefined', getUserId: () => undefined },
    ])
    .run(async ({ assert }, { getUserId }) => {
      const { provider, result } = await authenticateWithUserId(getUserId)

      assert.equal(result.status, 'rejected')
      if (result.status === 'rejected') {
        assert.instanceOf(result.reason, errors.E_UNAUTHORIZED_ACCESS)
      }
      // the database is never queried with an unexpected value
      assert.deepEqual(provider.ids, [])
    })

  test('reject the token with a 401 when getUserId throws', async ({ assert }) => {
    const { provider, result } = await authenticateWithUserId(() => {
      throw new TypeError("Cannot read properties of undefined (reading 'id')")
    })

    assert.equal(result.status, 'rejected')
    if (result.status === 'rejected') {
      assert.instanceOf(result.reason, errors.E_UNAUTHORIZED_ACCESS)
    }
    assert.deepEqual(provider.ids, [])
  })

  test('accept a user id that is {case}')
    .with([
      { case: 'a number', getUserId: (claims: Record<string, any>) => claims.userId, id: 1 },
      { case: 'a string', getUserId: (claims: Record<string, any>) => claims.sub, id: '1' },
      { case: 'a bigint', getUserId: (claims: Record<string, any>) => BigInt(claims.sub), id: 1n },
    ])
    .run(async ({ assert }, { getUserId, id }) => {
      const { provider, result } = await authenticateWithUserId(getUserId)

      assert.equal(result.status, 'fulfilled')
      assert.deepEqual(provider.ids, [id])
    })
})

test.group('Security | misuses are server errors, not 401s', (group) => {
  group.each.teardown(() => {
    nock.cleanAll()
  })

  const REFRESH_NOT_CONFIGURED =
    'JWT guard refresh tokens are not configured: set `refreshTokenUserProvider` in the guard config'
  const NO_SIGNING_IN_JWKS =
    'JWT guard cannot issue tokens in JWKS mode: tokens are issued by the identity provider'

  function jwksGuard() {
    const driver = new JwksDriver(
      { jwksUri: 'https://misuse.example.com/.well-known/jwks.json' },
      { issuer: 'idp', audience: 'api' }
    )
    return new JwtGuard(new HttpContextFactory().create(), new JwtFakeUserProvider(), { driver })
  }

  function guardWithoutRefreshTokens() {
    return new JwtGuard(new HttpContextFactory().create(), new JwtFakeUserProvider(), {
      secret: TEST_SECRET,
    })
  }

  test('{case}')
    .with([
      {
        case: 'generate() in JWKS mode',
        call: () => jwksGuard().generate({ id: 1, email: 'a@b.c', password: 'x' }),
        message: NO_SIGNING_IN_JWKS,
      },
      {
        case: 'generateWithRefreshToken() in JWKS mode',
        call: () => jwksGuard().generateWithRefreshToken('rt_whatever'),
        message: NO_SIGNING_IN_JWKS,
      },
      {
        case: 'generateWithRefreshToken() without refreshTokenUserProvider',
        call: () => guardWithoutRefreshTokens().generateWithRefreshToken('rt_whatever'),
        message: REFRESH_NOT_CONFIGURED,
      },
      {
        case: 'revoke() without refreshTokenUserProvider',
        call: () => guardWithoutRefreshTokens().revoke('rt_whatever'),
        message: REFRESH_NOT_CONFIGURED,
      },
    ])
    .run(async ({ assert }, { call, message }) => {
      const [result] = await Promise.allSettled([call()])

      assert.equal(result!.status, 'rejected')
      if (result!.status === 'rejected') {
        assert.instanceOf(result!.reason, RuntimeException)
        assert.notInstanceOf(result!.reason, errors.E_UNAUTHORIZED_ACCESS)
        assert.equal(result!.reason.message, message)
      }
    })
})

test.group('Security | Secret values for the signing keys', () => {
  test('accept a Secret as the symmetric secret', async ({ assert }) => {
    const userProvider = new JwtFakeUserProvider()
    const signer = new JwtGuard(new HttpContextFactory().create(), userProvider, {
      secret: new Secret(TEST_SECRET),
    })
    const { token } = await signer.generate((await userProvider.findById(1))!.getOriginal())

    // signed with the released value, not with "[redacted]"
    const guard = await authenticateWith({ secret: TEST_SECRET }, token)
    assert.equal(guard.user!.id, 1)
  })

  test('accept a Secret as the private key', async ({ assert }) => {
    const options = asymmetricGuardOptions('RS256')
    const userProvider = new JwtFakeUserProvider()
    const signer = new JwtGuard(new HttpContextFactory().create(), userProvider, {
      ...options,
      privateKey: new Secret(options.privateKey),
    })
    const { token } = await signer.generate((await userProvider.findById(1))!.getOriginal())

    const guard = await authenticateWith(options, token)
    assert.equal(guard.user!.id, 1)
  })

  test('jwtGuard() checks the length of a Secret on its released value', ({ assert }) => {
    assert.doesNotThrow(() =>
      jwtGuard({ provider: new JwtFakeUserProvider(), secret: new Secret(TEST_SECRET) })
    )
    assert.throws(
      () => jwtGuard({ provider: new JwtFakeUserProvider(), secret: new Secret('too-short') }),
      /at least 32 characters/
    )
  })

  test('throw at startup when the secret is {case}')
    .with([
      { case: 'a number', secret: 12345678901234567890123456789012345 },
      { case: 'an object without release()', secret: { value: TEST_SECRET } },
    ])
    .run(({ assert }, { secret }) => {
      assert.throws(
        () =>
          new JwtGuard(new HttpContextFactory().create(), new JwtFakeUserProvider(), {
            secret: secret as any,
          }),
        'JWT guard `secret` must be a string or a Secret'
      )
    })

  test('the defaults are not written into the options object of the caller', ({ assert }) => {
    const options = { secret: TEST_SECRET }
    new JwtGuard(new HttpContextFactory().create(), new JwtFakeUserProvider(), options)

    assert.deepEqual(options, { secret: TEST_SECRET })
  })
})

test.group('Security | empty claims are rejected at startup', () => {
  test('throw when {case} ({mode})')
    .with(
      (['symmetric', 'asymmetric'] as const).flatMap((mode) => [
        {
          mode,
          case: "issuer: ''",
          claims: { issuer: '' },
          message: /`issuer` must be a non-empty string/,
        },
        {
          mode,
          case: "issuer: '  '",
          claims: { issuer: '  ' },
          message: /`issuer` must be a non-empty string/,
        },
        {
          mode,
          case: 'audience: []',
          claims: { audience: [] },
          message: /`audience` must be a non-empty/,
        },
        {
          mode,
          case: "audience: ''",
          claims: { audience: '' },
          message: /`audience` must be a non-empty/,
        },
        {
          mode,
          case: "audience: ['api', '']",
          claims: { audience: ['api', ''] },
          message: /`audience` must be a non-empty/,
        },
      ])
    )
    .run(({ assert }, { mode, claims, message }) => {
      const keys = mode === 'symmetric' ? { secret: TEST_SECRET } : asymmetricGuardOptions('ES256')
      assert.throws(
        () =>
          new JwtGuard(new HttpContextFactory().create(), new JwtFakeUserProvider(), {
            ...keys,
            ...(claims as any),
          }),
        message
      )
    })

  test('accept a non-empty issuer and audience', ({ assert }) => {
    assert.doesNotThrow(
      () =>
        new JwtGuard(new HttpContextFactory().create(), new JwtFakeUserProvider(), {
          secret: TEST_SECRET,
          issuer: 'my-app',
          audience: ['web', 'mobile'],
        })
    )
  })

  test('throw at startup when JWKS is combined with refresh tokens', async ({ assert }) => {
    const { refreshTokenUserProvider } = await setupRefreshTokens()
    assert.throws(
      () =>
        jwtGuard({
          provider: new JwtFakeUserProvider(),
          jwks: { jwksUri: 'https://idp.example.com/.well-known/jwks.json' },
          issuer: 'idp',
          audience: 'api',
          refreshTokenUserProvider,
        }),
      /cannot use refresh tokens with `jwks`/
    )
  })
})

test.group('Security | refresh tokens expire after 7 days by default', () => {
  test('the database row, the cookie and the response agree', async ({ assert }) => {
    const { User, user, refreshTokenUserProvider } = await setupRefreshTokens()
    const ctx = new HttpContextFactory().create()
    const guard = new JwtGuard(ctx, new JwtFakeUserProvider(), {
      secret: TEST_SECRET,
      useCookies: true,
      useCookiesForRefreshToken: true,
      refreshTokenUserProvider,
    })

    const before = Date.now()
    const { refreshTokenExpiresIn } = await guard.generate(user)
    const sevenDays = 7 * 24 * 60 * 60

    assert.equal(refreshTokenExpiresIn, sevenDays)

    const [row] = await User.refreshTokens.all(user)
    const lifetime = (row!.expiresAt!.getTime() - before) / 1000
    assert.closeTo(lifetime, sevenDays, 60)

    const setCookie = ([] as string[]).concat(ctx.response.getHeader('set-cookie') as any)
    const refreshCookie = setCookie.find((cookie) => cookie.startsWith('refreshToken='))
    assert.include(refreshCookie, `Max-Age=${sevenDays}`)
  })

  test('a refresh token is rejected after 7 days', async ({ assert }) => {
    const { user, refreshTokenUserProvider } = await setupRefreshTokens()
    const options = { secret: TEST_SECRET, refreshTokenUserProvider }
    const { refreshToken } = await new JwtGuard(
      new HttpContextFactory().create(),
      new JwtFakeUserProvider(),
      options
    ).generate(user)

    timeTravel(7 * 24 * 60 * 60 + 60)

    await assert.rejects(
      () =>
        new JwtGuard(
          new HttpContextFactory().create(),
          new JwtFakeUserProvider(),
          options
        ).generateWithRefreshToken(refreshToken),
      errors.E_UNAUTHORIZED_ACCESS
    )
  })

  test('an explicit refreshTokenExpiresIn still wins', async ({ assert }) => {
    const { user, refreshTokenUserProvider } = await setupRefreshTokens()
    const { refreshTokenExpiresIn } = await new JwtGuard(
      new HttpContextFactory().create(),
      new JwtFakeUserProvider(),
      { secret: TEST_SECRET, refreshTokenExpiresIn: '30d', refreshTokenUserProvider }
    ).generate(user)

    assert.equal(refreshTokenExpiresIn, 30 * 24 * 60 * 60)
  })
})

test.group('Security | lifetimes in the generate() result are in seconds', () => {
  test('tokenExpiresIn {config} gives expiresIn {seconds}')
    .with([
      { config: '15m', seconds: 900 },
      { config: '1.5h', seconds: 5400 },
      { config: '1500ms', seconds: 1 },
      { config: 900, seconds: 900 },
    ])
    .run(async ({ assert }, { config, seconds }) => {
      const userProvider = new JwtFakeUserProvider()
      const guard = new JwtGuard(new HttpContextFactory().create(), userProvider, {
        secret: TEST_SECRET,
        tokenExpiresIn: config as any,
      })
      const result = await guard.generate((await userProvider.findById(1))!.getOriginal())

      assert.strictEqual(result.expiresIn, seconds)
      // a client can trust expiresIn: it matches the exp claim of the token
      const { iat, exp } = jwt.decode(result.token) as { iat: number; exp: number }
      assert.closeTo(exp - iat, seconds, 1)
    })

  test('without refresh tokens, refreshTokenExpiresIn is not set', async ({ assert }) => {
    const userProvider = new JwtFakeUserProvider()
    const result = await new JwtGuard(new HttpContextFactory().create(), userProvider, {
      secret: TEST_SECRET,
      refreshTokenExpiresIn: '7d',
    }).generate((await userProvider.findById(1))!.getOriginal())

    assert.notProperty(
      JSON.parse(JSON.stringify(result)),
      'refreshTokenExpiresIn',
      'no lifetime for a refresh token that was not issued'
    )
  })

  test('generateWithRefreshToken() returns seconds too', async ({ assert }) => {
    const { user, refreshTokenUserProvider } = await setupRefreshTokens()
    const options = {
      secret: TEST_SECRET,
      tokenExpiresIn: '10m' as const,
      refreshTokenUserProvider,
    }
    const { refreshToken } = await new JwtGuard(
      new HttpContextFactory().create(),
      new JwtFakeUserProvider(),
      options
    ).generate(user)

    const result = await new JwtGuard(
      new HttpContextFactory().create(),
      new JwtFakeUserProvider(),
      options
    ).generateWithRefreshToken(refreshToken)

    assert.strictEqual(result.expiresIn, 600)
    assert.strictEqual(result.refreshTokenExpiresIn, 7 * 24 * 60 * 60)
  })
})

test.group('Security | revoke (rc.8)', () => {
  test('revoke rejects a refresh token missing the configured abilities and keeps it valid', async ({
    assert,
  }) => {
    const { User, user, refreshTokenUserProvider } = await setupRefreshTokens()
    const ctx = new HttpContextFactory().create()

    const guard = new JwtGuard(ctx, new JwtFakeUserProvider(), {
      secret: TEST_SECRET,
      refreshTokenAbilities: ['admin_refresh'],
      refreshTokenUserProvider,
    })

    // a refresh token issued by another guard sharing the same provider
    const otherGuardToken = await User.refreshTokens.create(user, ['user_refresh'])

    await assert.rejects(
      () => guard.revoke(otherGuardToken.value!.release()),
      errors.E_UNAUTHORIZED_ACCESS
    )
    assert.isNotNull(await User.refreshTokens.verify(otherGuardToken.value!))
  })

  test('revoke keeps the cookies when the revocation fails with a non-401 error', async ({
    assert,
  }) => {
    const { User, user, refreshTokenUserProvider } = await setupRefreshTokens()
    const ctx = new HttpContextFactory().create()

    const guard = new JwtGuard(ctx, new JwtFakeUserProvider(), {
      secret: TEST_SECRET,
      useCookies: true,
      useCookiesForRefreshToken: true,
      refreshTokenUserProvider,
    })

    const refreshToken = await User.refreshTokens.create(user)
    const value = refreshToken.value!.release()
    const invalidateToken = refreshTokenUserProvider.invalidateToken.bind(refreshTokenUserProvider)
    refreshTokenUserProvider.invalidateToken = async () => {
      throw new Error('database is down')
    }

    await assert.rejects(() => guard.revoke(value), 'database is down')
    assert.isUndefined(ctx.response.getHeader('set-cookie'))

    // once the database is back, the client can retry the logout
    refreshTokenUserProvider.invalidateToken = invalidateToken
    await guard.revoke(value)
    assert.isNull(await User.refreshTokens.verify(new Secret(value)))
    const setCookie = ctx.response.getHeader('set-cookie') as string[]
    assert.isTrue(setCookie.some((c) => c.startsWith('refreshToken=;') && c.includes('Max-Age=0')))
  })

  test('two guards with a distinct token type do not accept each other refresh tokens', async ({
    assert,
  }) => {
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
      // same table, one `type` per guard
      static refreshTokens = DbAccessTokensProvider.forModel(User, {
        table: 'jwt_refresh_tokens',
        type: 'jwt_refresh_token',
      })
      static adminRefreshTokens = DbAccessTokensProvider.forModel(User, {
        table: 'jwt_refresh_tokens',
        type: 'jwt_admin_refresh_token',
      })
    }
    const model = async () => ({ default: User })
    const user = await User.create({
      email: 'two_guards@example.com',
      username: 'two_guards',
      password: 'password',
    })

    const makeGuards = () => {
      const ctx = new HttpContextFactory().create()
      return {
        jwt: new JwtGuard(ctx, new JwtFakeUserProvider(), {
          secret: TEST_SECRET,
          refreshTokenUserProvider: tokensUserProvider({ tokens: 'refreshTokens', model }),
        }),
        admin: new JwtGuard(ctx, new JwtFakeUserProvider(), {
          secret: TEST_SECRET,
          refreshTokenUserProvider: tokensUserProvider({ tokens: 'adminRefreshTokens', model }),
        }),
      }
    }

    const userRefreshToken = await User.refreshTokens.create(user)
    const adminRefreshToken = await User.adminRefreshTokens.create(user)
    const userToken = userRefreshToken.value!.release()
    const adminToken = adminRefreshToken.value!.release()

    let guards = makeGuards()
    await assert.rejects(
      () => guards.admin.generateWithRefreshToken(userToken),
      'Unauthorized access'
    )
    await assert.rejects(
      () => guards.jwt.generateWithRefreshToken(adminToken),
      'Unauthorized access'
    )
    await assert.rejects(() => guards.admin.revoke(userToken), errors.E_UNAUTHORIZED_ACCESS)
    await assert.rejects(() => guards.jwt.revoke(adminToken), errors.E_UNAUTHORIZED_ACCESS)

    // both tokens are still valid for their own guard
    guards = makeGuards()
    await guards.jwt.revoke(userToken)
    await guards.admin.revoke(adminToken)
  })
})
