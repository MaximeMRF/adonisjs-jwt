/*
|--------------------------------------------------------------------------
| Package entrypoint
|--------------------------------------------------------------------------
|
| Export values from the package entrypoint as you see fit.
|
*/

export { configure } from './configure.js'
export { jwtGuard } from './src/define_config.js'
export { JwtGuard } from './src/guard.js'
export { DEFAULT_TOKEN_EXPIRES_IN } from './src/types.js'
