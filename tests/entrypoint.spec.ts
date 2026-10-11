import { test } from '@japa/runner'

test.group('Package entrypoint', () => {
  test('exports the public API from the main entrypoint', async ({ assert }) => {
    const main = await import('../index.js')
    const { jwtGuard } = await import('../src/define_config.js')
    const { JwtGuard } = await import('../src/guard.js')

    assert.strictEqual(main.jwtGuard, jwtGuard)
    assert.strictEqual(main.JwtGuard, JwtGuard)
    assert.equal(main.DEFAULT_TOKEN_EXPIRES_IN, '1h')
    assert.isFunction(main.configure)
  })
})
