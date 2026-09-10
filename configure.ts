/*
|--------------------------------------------------------------------------
| Configure hook
|--------------------------------------------------------------------------
|
| The configure hook is called when someone runs "node ace configure <package>"
| command. You are free to perform any operations inside this function to
| configure the package.
|
*/

import type ConfigureCommand from '@adonisjs/core/commands/configure'
import { stubsRoot } from './stubs/main.js'

export async function configure(command: ConfigureCommand) {
  const codemods = await command.createCodemods()

  const createMigration = await command.prompt.confirm(
    'Do you want to create the database migration for JWT refresh tokens?',
    { default: true }
  )

  if (createMigration) {
    const time = new Date().getTime()
    await codemods.makeUsingStub(stubsRoot, 'migration.stub', {
      entity: {
        filename: `${time}_create_jwt_refresh_tokens_table.ts`,
      },
    })
  }
}
