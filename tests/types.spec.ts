import { test } from '@japa/runner'
import { symbols } from '@adonisjs/auth'
import { jwtGuard } from '../src/define_config.js'
import { JwtFakeUserProvider } from '../factories/main.js'
import type { JwtGuardConfig, JwtGuardUser, JwtUserProviderContract } from '../src/types.js'
import { TEST_SECRET as SECRET } from './helpers.js'

/**
 * These tests are checked by `tsc --noEmit` (`npm run typecheck`): an
 * unused `@ts-expect-error` fails the typecheck
 */
test.group('Public types', () => {
  test('content must set userId when getUserId is not defined', ({ assert }) => {
    const provider = new JwtFakeUserProvider()

    // @ts-expect-error the guard reads the user id from the userId claim
    jwtGuard({
      provider,
      secret: SECRET,
      content: (user) => ({ sub: String(user.getId()) }),
    })

    jwtGuard({
      provider,
      secret: SECRET,
      content: (user) => ({ userId: user.getId(), role: 'admin' }),
    })

    assert.isTrue(true)
  })

  test('content may omit userId when getUserId is defined', ({ assert }) => {
    const config: JwtGuardConfig<JwtFakeUserProvider> = {
      provider: new JwtFakeUserProvider(),
      secret: SECRET,
      getUserId: (payload) => payload.sub,
      content: (user) => ({ sub: String(user.getId()) }),
    }

    assert.doesNotThrow(() => jwtGuard(config))
  })

  test('content must not set exp, which comes from tokenExpiresIn', ({ assert }) => {
    const provider = new JwtFakeUserProvider()

    jwtGuard({
      provider,
      secret: SECRET,
      // @ts-expect-error the guard sets exp from tokenExpiresIn
      content: (user) => ({ userId: user.getId(), exp: Math.floor(Date.now() / 1000) + 60 }),
    })

    jwtGuard({
      provider,
      secret: SECRET,
      getUserId: (payload) => payload.sub,
      // @ts-expect-error also with getUserId
      content: (user) => ({ sub: String(user.getId()), exp: 0 }),
    })

    assert.isTrue(true)
  })

  test('user providers must declare the real user type', ({ assert }) => {
    type Service = { id: string }

    // @ts-expect-error [symbols.PROVIDER_REAL_USER] is required
    class WithoutRealUser implements JwtUserProviderContract<Service> {
      async createUserForGuard(service: Service): Promise<JwtGuardUser<Service>> {
        return { getId: () => service.id, getOriginal: () => service }
      }
      async findById() {
        return null
      }
    }

    class WithRealUser implements JwtUserProviderContract<Service> {
      declare [symbols.PROVIDER_REAL_USER]: Service
      async createUserForGuard(service: Service): Promise<JwtGuardUser<Service>> {
        return { getId: () => service.id, getOriginal: () => service }
      }
      async findById() {
        return null
      }
    }

    assert.isFunction(WithoutRealUser)
    assert.isFunction(WithRealUser)
  })

  test('the types entrypoint only exports types', async ({ assert }) => {
    const types = await import('../src/types.js')
    assert.deepEqual(Object.keys(types), [])
  })

  test('jwtGuard does not accept a driver', ({ assert }) => {
    jwtGuard({
      provider: new JwtFakeUserProvider(),
      secret: SECRET,
      // @ts-expect-error drivers are internal
      driver: { canSign: true, sign: () => '', verify: () => ({}) },
    })

    assert.isTrue(true)
  })
})
