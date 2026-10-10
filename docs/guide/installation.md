# Installation

## Prerequisites

The guard relies on the AdonisJS auth package. Install it first if your application doesn't use it yet:

```sh
node ace add @adonisjs/auth
```

## Install the package

```sh
npm i @maximemrf/adonisjs-jwt
```

Then run the configure command:

```sh
node ace configure @maximemrf/adonisjs-jwt
```

`node ace add @maximemrf/adonisjs-jwt` does both steps at once.

The command asks whether you want to use [refresh tokens](/guide/refresh-tokens), then:

- adds a `jwt` guard to `config/auth.ts`. It doesn't change the `default` guard;
- with refresh tokens:
  - adds a `refreshTokens` provider to `app/models/user.ts`,
  - creates the migration of the `jwt_refresh_tokens` table;
- prints the next steps.

It keeps the style of your files and leaves existing code untouched: running it again doesn't duplicate anything. When a file doesn't have the expected shape, it prints the code to add yourself.

Pass `--refresh-tokens` or `--no-refresh-tokens` to skip the question, for example in a script:

```sh
node ace configure @maximemrf/adonisjs-jwt --no-refresh-tokens
```

With refresh tokens, run the migration:

```sh
node ace migration:run
```

::: tip AdonisJS v6
Install the `0.7.x` version, the last one that supports AdonisJS v6:

```sh
npm i @maximemrf/adonisjs-jwt@0.7.1
```

The rest of this documentation describes the latest version.
:::

## Next step

[Configure the guard](/guide/configuration) in `config/auth.ts`.
