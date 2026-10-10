/*
|--------------------------------------------------------------------------
| Configure hook
|--------------------------------------------------------------------------
|
| Called by "node ace configure @maximemrf/adonisjs-jwt" (and "node ace add").
| Adds the jwt guard to config/auth.ts and, with refresh tokens, the
| refreshTokens provider to the User model and the migration.
|
| Flags: --refresh-tokens / --no-refresh-tokens to skip the question.
|
*/

import { existsSync, readdirSync } from 'node:fs'
import type ConfigureCommand from '@adonisjs/core/commands/configure'
import type {
  CallExpression,
  ClassDeclaration,
  ObjectLiteralExpression,
  Project,
  PropertyAssignment,
  SourceFile,
} from 'ts-morph'
import { stubsRoot } from './stubs/main.js'

const DOCS_URL = 'https://maximemrf.github.io/adonisjs-jwt'
const MIGRATION_SUFFIX = '_create_jwt_refresh_tokens_table.ts'

const GUARD = `jwtGuard({
  provider: sessionUserProvider({
    model: () => import('#models/user'),
  }),
})`

const GUARD_WITH_REFRESH_TOKENS = `jwtGuard({
  provider: sessionUserProvider({
    model: () => import('#models/user'),
  }),
  refreshTokenUserProvider: tokensUserProvider({
    tokens: 'refreshTokens',
    model: () => import('#models/user'),
  }),
  refreshTokenExpiresIn: '7d',
})`

const refreshTokensProvider = (
  modelName: string
) => `DbAccessTokensProvider.forModel(${modelName}, {
  prefix: 'rt_',
  table: 'jwt_refresh_tokens',
  type: 'jwt_refresh_token',
  tokenSecretLength: 40,
})`

export async function configure(command: ConfigureCommand) {
  const authConfigPath = command.app.configPath('auth.ts')
  if (!existsSync(authConfigPath)) {
    command.logger.error(
      'Cannot find "config/auth.ts". Run "node ace add @adonisjs/auth" first, then run this command again'
    )
    command.exitCode = 1
    return
  }

  const refreshTokens = await useRefreshTokens(command)
  const codemods = await command.createCodemods()
  const project = await codemods.getTsMorphProject()

  await addGuard(command, project, authConfigPath, refreshTokens)

  if (refreshTokens) {
    await addRefreshTokensToModel(command, project)
    await createMigration(command, codemods)
  }

  command.logger.info('Next steps:')
  if (refreshTokens) {
    command.logger.log('  - Run "node ace migration:run" to create the jwt_refresh_tokens table')
  }
  command.logger.log(
    `  - Set default: 'jwt' in config/auth.ts, or use auth.use('jwt') in your routes`
  )
  command.logger.log(
    `  - Add the login, refresh and logout routes: ${DOCS_URL}/guide/authentication`
  )
}

/**
 * Read the --refresh-tokens / --no-refresh-tokens flag, or ask
 */
async function useRefreshTokens(command: ConfigureCommand): Promise<boolean> {
  const flag = command.parsedFlags['refresh-tokens']
  if (flag !== undefined) {
    return flag === true || flag === 'true'
  }

  return command.prompt.confirm('Do you want to use refresh tokens?', { default: true })
}

/**
 * Add the "jwt" guard to the guards of config/auth.ts
 */
async function addGuard(
  command: ConfigureCommand,
  project: Project | undefined,
  authConfigPath: string,
  refreshTokens: boolean
) {
  const action = command.logger.action('update config/auth.ts')
  const guard = refreshTokens ? GUARD_WITH_REFRESH_TOKENS : GUARD

  const file = project ? getSourceFile(project, authConfigPath) : undefined
  const guards = file ? findGuardsObject(file) : undefined
  if (!file || !guards) {
    action.skipped(`add this guard to config/auth.ts manually: jwt: ${guard}`)
    return
  }

  if (guards.getProperty('jwt')) {
    action.skipped('a "jwt" guard already exists')
    return
  }

  addProperty(guards, `jwt: ${guard}`)
  ensureNamedImport(file, '@maximemrf/adonisjs-jwt', 'jwtGuard')
  ensureNamedImport(file, '@adonisjs/auth/session', 'sessionUserProvider')
  if (refreshTokens) {
    ensureNamedImport(file, '@adonisjs/auth/access_tokens', 'tokensUserProvider')
  }

  await file.save()
  action.succeeded()
}

/**
 * Add the static refreshTokens property to the User model
 */
async function addRefreshTokensToModel(command: ConfigureCommand, project: Project | undefined) {
  const modelPath = command.app.modelsPath('user.ts')
  const action = command.logger.action('update app/models/user.ts')

  const file = project && existsSync(modelPath) ? getSourceFile(project, modelPath) : undefined
  const model = file ? findModel(file) : undefined
  if (!file || !model) {
    action.skipped(
      `add this property to your User model manually: static refreshTokens = ${refreshTokensProvider('User')}`
    )
    return
  }

  if (model.getStaticProperty('refreshTokens')) {
    action.skipped('the model already has a "refreshTokens" property')
    return
  }

  addClassMember(
    model,
    `static refreshTokens = ${refreshTokensProvider(model.getName() ?? 'User')}${semicolon(file)}`
  )
  ensureNamedImport(file, '@adonisjs/auth/access_tokens', 'DbAccessTokensProvider')

  await file.save()
  action.succeeded()
}

/**
 * Create the migration of the jwt_refresh_tokens table, unless it exists
 */
async function createMigration(
  command: ConfigureCommand,
  codemods: Awaited<ReturnType<ConfigureCommand['createCodemods']>>
) {
  const migrationsPath = command.app.migrationsPath()
  const existing = existsSync(migrationsPath)
    ? readdirSync(migrationsPath).find((file) => file.endsWith(MIGRATION_SUFFIX))
    : undefined

  if (existing) {
    command.logger
      .action(`create database/migrations/${existing}`)
      .skipped('the migration already exists')
    return
  }

  await codemods.makeUsingStub(stubsRoot, 'migration.stub', {
    entity: {
      filename: `${Date.now()}${MIGRATION_SUFFIX}`,
    },
  })
}

function getSourceFile(project: Project, path: string): SourceFile {
  return project.getSourceFile(path) ?? project.addSourceFileAtPath(path)
}

/**
 * Find the object literal of `defineConfig({ guards: { ... } })`
 */
function findGuardsObject(file: SourceFile): ObjectLiteralExpression | undefined {
  const call = file
    .getDescendants()
    .find(
      (node) =>
        node.getKindName() === 'CallExpression' &&
        (node as CallExpression).getExpression().getText() === 'defineConfig'
    ) as CallExpression | undefined

  const config = call?.getArguments()[0]
  if (config?.getKindName() !== 'ObjectLiteralExpression') {
    return
  }

  const guards = (config as ObjectLiteralExpression).getProperty('guards')
  if (guards?.getKindName() !== 'PropertyAssignment') {
    return
  }

  const initializer = (guards as PropertyAssignment).getInitializer()
  if (initializer?.getKindName() !== 'ObjectLiteralExpression') {
    return
  }

  return initializer as ObjectLiteralExpression
}

/**
 * The default exported class of the file, or the class named User
 */
function findModel(file: SourceFile): ClassDeclaration | undefined {
  const classes = file.getClasses()
  return (
    classes.find((cls) => cls.isDefaultExport()) ?? classes.find((cls) => cls.getName() === 'User')
  )
}

/**
 * The edits below insert text rather than ts-morph structures, to keep the
 * indentation, trailing commas and semicolons style of the user's files
 */

function semicolon(file: SourceFile) {
  return file.getStatements()[0]?.getText().trimEnd().endsWith(';') ? ';' : ''
}

/**
 * Leading whitespace of the line containing the given position
 */
function lineIndentation(file: SourceFile, position: number) {
  const text = file.getFullText()
  const lineStart = text.lastIndexOf('\n', position - 1) + 1
  return text.slice(lineStart).match(/^[ \t]*/)![0]
}

/**
 * Indent every line but the first one
 */
function indent(code: string, indentation: string) {
  return code.replaceAll('\n', `\n${indentation}`)
}

/**
 * Add a property after the last property of an object literal
 */
function addProperty(object: ObjectLiteralExpression, property: string) {
  const file = object.getSourceFile()
  const last = object.getProperties().at(-1)

  if (!last) {
    const baseIndentation = lineIndentation(file, object.getStart())
    const indentation = `${baseIndentation}  `
    file.replaceText(
      [object.getStart(), object.getEnd()],
      `{\n${indentation}${indent(property, indentation)},\n${baseIndentation}}`
    )
    return
  }

  const indentation = lineIndentation(file, last.getStart())
  const text = file.getFullText()
  const hasTrailingComma = text.slice(last.getEnd()).trimStart().startsWith(',')
  const position = hasTrailingComma ? text.indexOf(',', last.getEnd()) + 1 : last.getEnd()

  file.insertText(
    position,
    `${hasTrailingComma ? '' : ','}\n${indentation}${indent(property, indentation)},`
  )
}

/**
 * Add a member at the end of a class body
 */
function addClassMember(cls: ClassDeclaration, member: string) {
  const file = cls.getSourceFile()
  const last = cls.getMembers().at(-1)

  if (!last) {
    const closingBrace = cls.getEnd() - 1
    const openingBrace = file.getFullText().lastIndexOf('{', closingBrace)
    const baseIndentation = lineIndentation(file, cls.getStart())
    const indentation = `${baseIndentation}  `
    file.replaceText(
      [openingBrace, closingBrace + 1],
      `{\n${indentation}${indent(member, indentation)}\n${baseIndentation}}`
    )
    return
  }

  const indentation = lineIndentation(file, last.getStart())
  file.insertText(last.getEnd(), `\n\n${indentation}${indent(member, indentation)}`)
}

function ensureNamedImport(file: SourceFile, moduleSpecifier: string, name: string) {
  const declaration = file.getImportDeclaration(
    (node) => node.getModuleSpecifierValue() === moduleSpecifier && !node.isTypeOnly()
  )

  if (declaration) {
    if (!declaration.getNamedImports().some((namedImport) => namedImport.getName() === name)) {
      declaration.addNamedImport(name)
    }
    return
  }

  const statement = `import { ${name} } from '${moduleSpecifier}'${semicolon(file)}`
  const lastImport = file.getImportDeclarations().at(-1)
  if (lastImport) {
    file.insertText(lastImport.getEnd(), `\n${statement}`)
  } else {
    file.insertText(0, `${statement}\n\n`)
  }
}
