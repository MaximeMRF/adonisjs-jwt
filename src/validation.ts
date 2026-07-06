import type { JwtGuardOptions } from './types.js'

export function validateGuardOptions(options: JwtGuardOptions, prefix: string = 'JwtGuard') {
  if (options.driver) {
    return
  }

  const asymmetricPartial =
    options.privateKey !== undefined ||
    options.publicKey !== undefined ||
    options.algorithm !== undefined

  const usesAsymmetric =
    options.privateKey !== undefined &&
    options.publicKey !== undefined &&
    options.algorithm !== undefined

  if (asymmetricPartial && !usesAsymmetric) {
    throw new Error(
      `${prefix} asymmetric mode requires \`privateKey\`, \`publicKey\`, and \`algorithm\` to be set together`
    )
  }

  if (options.jwks && usesAsymmetric) {
    throw new Error(
      `${prefix} cannot use \`jwks\` together with asymmetric \`privateKey\` / \`publicKey\``
    )
  }

  if (!options.jwks && !usesAsymmetric && !options.secret) {
    throw new Error(
      `${prefix} requires \`secret\` (symmetric), or \`privateKey\` + \`publicKey\` + \`algorithm\` (asymmetric), or \`jwks\``
    )
  }
}
