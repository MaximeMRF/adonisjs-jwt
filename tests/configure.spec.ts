import { test } from '@japa/runner'
import { configure } from '../configure.js'
import { AppFactory } from '@adonisjs/core/factories/app'
import { LoggerFactory } from '@adonisjs/core/factories/logger'
import ConfigureCommand from '@adonisjs/core/commands/configure'

test.group('Configure hook', () => {
  test('configure should generate migration file on disk when confirmed', async ({
    assert,
    fs,
  }) => {
    await fs.mkdir('app')
    const app = new AppFactory().create(fs.baseUrl, () => {})
    await app.init()

    const logger = new LoggerFactory().create() as any
    logger.action = () => ({ succeeded: () => {}, failed: () => {}, skipped: () => {} })

    const command = new ConfigureCommand(app as any, {} as any, {} as any, logger, {} as any)
    command.ui = { logger } as any
    command.prompt = {
      confirm: async () => true,
    } as any

    await configure(command)

    const files = (await fs.readDir('database/migrations')) as any
    assert.lengthOf(files, 1)

    const targetFile = files[0]
    const fileName =
      typeof targetFile === 'string'
        ? targetFile
        : typeof targetFile === 'object' && targetFile
          ? (targetFile.name ??
            targetFile.relativePath ??
            targetFile.path ??
            JSON.stringify(targetFile))
          : String(targetFile)

    assert.isTrue(
      fileName.endsWith('_create_jwt_refresh_tokens_table.ts'),
      `Expected ${fileName} to end with _create_jwt_refresh_tokens_table.ts`
    )

    const content = await fs.contents(`database/migrations/${fileName}`)
    assert.include(content, "protected tableName = 'jwt_refresh_tokens'")
    assert.include(content, 'this.schema.createTable(this.tableName')
  })

  test('configure should skip creating migration file when declined', async ({ assert, fs }) => {
    await fs.mkdir('app')
    const app = new AppFactory().create(fs.baseUrl, () => {})
    await app.init()

    const logger = new LoggerFactory().create() as any
    logger.action = () => ({ succeeded: () => {}, failed: () => {}, skipped: () => {} })

    const command = new ConfigureCommand(app as any, {} as any, {} as any, logger, {} as any)
    command.ui = { logger } as any
    command.prompt = {
      confirm: async () => false,
    } as any

    await configure(command)

    const exists = await fs.exists('database/migrations')
    assert.isFalse(exists)
  })
})
