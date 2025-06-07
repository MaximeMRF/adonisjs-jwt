import timekeeper from 'timekeeper'
import { getActiveTest } from '@japa/runner'
import { BaseModel } from '@adonisjs/lucid/orm'
import { AppFactory } from '@adonisjs/core/factories/app'
import { mkdir, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { Emitter } from '@adonisjs/core/events'
import { LoggerFactory } from '@adonisjs/core/factories/logger'
import { Database } from '@adonisjs/lucid/database'

/**
 * Travels time by seconds
 */
export function timeTravel(secondsToTravel: number) {
  const test = getActiveTest()
  if (!test) {
    throw new Error('Cannot use "timeTravel" outside of a Japa test')
  }

  timekeeper.reset()

  const date = new Date()
  date.setSeconds(date.getSeconds() + secondsToTravel)
  timekeeper.travel(date)

  test.cleanup(() => {
    timekeeper.reset()
  })
}

/**
 * Freezes time in the moment
 */
export function freezeTime() {
  const test = getActiveTest()
  if (!test) {
    throw new Error('Cannot use "freezeTime" outside of a Japa test')
  }

  timekeeper.reset()

  const date = new Date()
  timekeeper.freeze(date)

  test.cleanup(() => {
    timekeeper.reset()
  })
}

/**
 * Creates an instance of the database class for making queries
 */
export async function createDatabase() {
  const test = getActiveTest()
  if (!test) {
    throw new Error('Cannot use "createDatabase" outside of a Japa test')
  }

  const basePath = test.context.fs.basePath
  await mkdir(basePath)

  const app = new AppFactory().create(test.context.fs.baseUrl, () => {})
  const logger = new LoggerFactory().create()
  const emitter = new Emitter(app)
  const db = new Database(
    {
      connection: process.env.DB || 'sqlite',
      connections: {
        sqlite: {
          client: 'sqlite3',
          connection: {
            filename: join(test.context.fs.basePath, 'db.sqlite3'),
          },
        },
        pg: {
          client: 'pg',
          connection: {
            host: process.env.PG_HOST as string,
            port: Number(process.env.PG_PORT),
            database: process.env.PG_DATABASE as string,
            user: process.env.PG_USER as string,
            password: process.env.PG_PASSWORD as string,
          },
        },
        mssql: {
          client: 'mssql',
          connection: {
            server: process.env.MSSQL_HOST as string,
            port: Number(process.env.MSSQL_PORT! as string),
            user: process.env.MSSQL_USER as string,
            password: process.env.MSSQL_PASSWORD as string,
            database: 'master',
            options: {
              enableArithAbort: true,
            },
          },
        },
        mysql: {
          client: 'mysql2',
          connection: {
            host: process.env.MYSQL_HOST as string,
            port: Number(process.env.MYSQL_PORT),
            database: process.env.MYSQL_DATABASE as string,
            user: process.env.MYSQL_USER as string,
            password: process.env.MYSQL_PASSWORD as string,
          },
        },
      },
    },
    logger,
    emitter
  )

  test.cleanup(async () => {
    db.manager.closeAll()
    await rm(basePath, { force: true, recursive: true, maxRetries: 3 })
  })
  BaseModel.useAdapter(db.modelAdapter())
  return db
}

/**
 * Creates needed database tables
 */
export async function createTables(db: Database) {
  const test = getActiveTest()
  if (!test) {
    throw new Error('Cannot use "createTables" outside of a Japa test')
  }

  test.cleanup(async () => {
    await db.connection().schema.dropTable('users')
    await db.connection().schema.dropTable('jwt_refresh_tokens')
  })

  await db.connection().schema.createTable('jwt_refresh_tokens', (table) => {
    table.increments()
    table.integer('tokenable_id').notNullable().unsigned()
    table.string('type').notNullable()
    table.string('name').nullable()
    table.string('hash', 80).notNullable()
    table.text('abilities').notNullable()
    table.timestamp('created_at', { precision: 6, useTz: true }).notNullable()
    table.timestamp('updated_at', { precision: 6, useTz: true }).notNullable()
    table.timestamp('expires_at', { precision: 6, useTz: true }).nullable()
    table.timestamp('last_used_at', { precision: 6, useTz: true }).nullable()
  })

  await db.connection().schema.createTable('users', (table) => {
    table.increments()
    table.string('username').unique().notNullable()
    table.string('email').unique().notNullable()
    table.string('password').nullable()
  })
}
