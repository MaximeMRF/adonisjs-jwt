import { symbols, errors } from '@adonisjs/auth'
import { RuntimeException } from '@adonisjs/core/exceptions'
import type { AuthClientResponse, GuardContract } from '@adonisjs/auth/types'
import type { HttpContext } from '@adonisjs/core/http'
import { DEFAULT_REFRESH_TOKEN_EXPIRES_IN, DEFAULT_TOKEN_EXPIRES_IN } from './constants.js'
import type {
  JwtUserProviderContract,
  JwtGuardOptions,
  JwtCookieOptions,
  JwtGenerateResult,
} from './types.js'
import { Secret } from '@adonisjs/core/helpers'
import type { AccessTokensUserProviderContract } from '@adonisjs/auth/types/access_tokens'
import type { JwtDriver, JwtGuardInternalOptions } from './drivers/types.js'
import {
  releaseSecrets,
  toSeconds,
  validateGuardOptions,
  type ReleasedSecrets,
} from './validation.js'
import { resolveDriver } from './driver_resolver.js'
import { installJwtUnauthorizedRenderer } from './errors.js'

installJwtUnauthorizedRenderer()

export class JwtGuard<
  UserProvider extends JwtUserProviderContract<unknown>,
  WithRefreshToken extends boolean = boolean,
> implements GuardContract<UserProvider[typeof symbols.PROVIDER_REAL_USER]> {
  #ctx: HttpContext
  #userProvider: UserProvider
  #refreshTokenUserProvider?: AccessTokensUserProviderContract<
    UserProvider[typeof symbols.PROVIDER_REAL_USER]
  >
  #options: ReleasedSecrets<
    JwtGuardOptions<UserProvider[typeof symbols.PROVIDER_REAL_USER]> & JwtGuardInternalOptions
  >
  #tokenName: string
  #refreshTokenName: string = 'refreshToken'
  #driver: JwtDriver
  #cookieOptions?: JwtCookieOptions | undefined
  /**
   * Refresh token issued during the current request, by `generate()` or a
   * refresh. A logout in the same request revokes it: the request still
   * carries the previous one, which the refresh has already deleted.
   */
  #issuedRefreshToken?: string

  constructor(
    ctx: HttpContext,
    userProvider: UserProvider,
    option: JwtGuardOptions<UserProvider[typeof symbols.PROVIDER_REAL_USER]> &
      JwtGuardInternalOptions
  ) {
    this.#ctx = ctx
    this.#userProvider = userProvider
    /**
     * Copy the options: the defaults below must not leak into the caller's object
     */
    this.#options = releaseSecrets({ ...option })
    this.#refreshTokenUserProvider = this.#options.refreshTokenUserProvider
    if (!this.#options.content) this.#options.content = (user) => ({ userId: user.getId() })
    this.#tokenName = this.#options.tokenName ?? 'token'
    this.#refreshTokenName = this.#options.refreshTokenName ?? 'refreshToken'
    /**
     * Never issue access tokens without an expiration
     */
    this.#options.tokenExpiresIn = this.#options.tokenExpiresIn ?? DEFAULT_TOKEN_EXPIRES_IN
    /**
     * Give refresh tokens a lifetime, so the database row, the cookie and
     * the response always agree
     */
    if (this.#refreshTokenUserProvider) {
      this.#options.refreshTokenExpiresIn =
        this.#options.refreshTokenExpiresIn ?? DEFAULT_REFRESH_TOKEN_EXPIRES_IN
    }
    this.#cookieOptions = {
      httpOnly: true,
      secure: true,
      ...this.#options.cookie,
    }

    validateGuardOptions(this.#options, 'JWT guard')
    this.#driver = resolveDriver(this.#options, 'JWT guard')
  }

  #signAccessToken(payload: Record<string, any>) {
    return this.#driver.sign(payload, { expiresIn: this.#options.tokenExpiresIn! })
  }

  async #verifyAccessToken(token: string) {
    return this.#driver.verify(token)
  }

  #extractToken(): string | undefined {
    /**
     * The header is set explicitly by the client, so it takes precedence
     * over the cookie, which the browser sends on every request (a stale
     * cookie must not shadow a valid bearer token)
     */
    const authHeader = this.#ctx.request.header('authorization')
    if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
      const headerToken = authHeader.slice(7).trim()
      if (headerToken) {
        return headerToken
      }
    }

    if (this.#options.useCookies) {
      const cookieToken = this.#ctx.request.cookie(this.#tokenName)
      if (cookieToken) {
        return cookieToken
      }
    }

    return undefined
  }
  /**
   * A list of events and their types emitted by
   * the guard.
   */
  declare [symbols.GUARD_KNOWN_EVENTS]: {}

  /**
   * A unique name for the guard driver
   */
  driverName: 'jwt' = 'jwt'

  /**
   * A flag to know if the authentication was an attempt
   * during the current HTTP request
   */
  authenticationAttempted: boolean = false

  /**
   * A boolean to know if the current request has
   * been authenticated
   */
  isAuthenticated: boolean = false

  /**
   * Reference to the currently authenticated user
   */
  user?: UserProvider[typeof symbols.PROVIDER_REAL_USER] & { currentToken: string }

  /**
   * Generate a JWT token for a given user.
   */
  async generate(
    user: UserProvider[typeof symbols.PROVIDER_REAL_USER]
  ): Promise<JwtGenerateResult<WithRefreshToken>> {
    if (!this.#driver.canSign) {
      throw new RuntimeException(
        'JWT guard cannot issue tokens in JWKS mode: tokens are issued by the identity provider'
      )
    }
    const providerUser = await this.#userProvider.createUserForGuard(user)

    const signPayload: Record<string, any> = this.#options.content!(providerUser)
    assertNoGuardClaims(signPayload, this.#options)
    const token = this.#signAccessToken(signPayload)

    let refreshToken
    if (this.#refreshTokenUserProvider) {
      const generatedRefreshToken = await this.#refreshTokenUserProvider.createToken(
        user,
        this.#options.refreshTokenAbilities ?? [],
        /**
         * Always set when there is a refresh token provider (7 days by default)
         */
        { expiresIn: this.#options.refreshTokenExpiresIn! }
      )
      refreshToken = generatedRefreshToken.value!.release()
      this.#issuedRefreshToken = refreshToken
    }

    if (this.#options.useCookies) {
      this.#ctx.response.cookie(`${this.#tokenName}`, token, {
        ...this.#cookieOptions,
        maxAge: this.#options.tokenExpiresIn,
      })
    }

    if (this.#options.useCookiesForRefreshToken && refreshToken) {
      this.#ctx.response.cookie(`${this.#refreshTokenName}`, refreshToken, {
        ...this.#cookieOptions,
        maxAge: this.#options.refreshTokenExpiresIn,
      })
    }

    return {
      type: 'bearer',
      token: token,
      expiresIn: toSeconds(this.#options.tokenExpiresIn!),
      refreshToken: refreshToken,
      refreshTokenExpiresIn: refreshToken
        ? toSeconds(this.#options.refreshTokenExpiresIn!)
        : undefined,
    } as JwtGenerateResult<WithRefreshToken>
  }

  /**
   * Authenticate the current HTTP request and return
   * the user instance if there is a valid JWT token
   * or throw an exception
   */
  async authenticate(): Promise<
    UserProvider[typeof symbols.PROVIDER_REAL_USER] & { currentToken: string }
  > {
    /**
     * Avoid re-authentication when it has been done already
     * for the given request
     */
    if (this.authenticationAttempted) {
      return this.getUserOrFail()
    }
    this.authenticationAttempted = true

    /**
     * Read the token from the Authorization header or the cookie
     */
    const token = this.#extractToken()
    if (!token) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    /**
     * Verify token
     */
    let payload

    try {
      payload = await this.#verifyAccessToken(token)
    } catch {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    /**
     * jsonwebtoken only checks `exp` when the claim is present: a token
     * without it (issued by another service sharing the secret, or by an
     * identity provider) would otherwise be valid forever
     */
    if (!payload || typeof payload !== 'object' || typeof payload.exp !== 'number') {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    if (this.#options.verifyPayload) {
      /**
       * Only an explicit `true` accepts the token: a truthy value such as
       * a claim or an error message must not let it through. A callback
       * that throws rejects the token instead of failing the request.
       */
      let isValid: unknown = false
      try {
        isValid = await this.#options.verifyPayload(payload)
      } catch {}

      if (isValid !== true) {
        throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
          guardDriverName: this.driverName,
        })
      }
    }

    /**
     * A `getUserId` that throws, or a claim of an unexpected type (an object
     * or an array from an identity provider), rejects the token instead of
     * failing the request or reaching the database
     */
    let userId: unknown
    try {
      userId = (this.#options.getUserId ?? ((claims) => claims.userId))(payload)
    } catch {}
    if (!isUserId(userId)) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    /**
     * Fetch the user by user ID and save a reference to it
     */
    const providerUser = await this.#userProvider.findById(userId)
    if (!providerUser) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    this.isAuthenticated = true
    this.user = providerUser.getOriginal() as UserProvider[typeof symbols.PROVIDER_REAL_USER] & {
      currentToken: string
    }
    this.user!.currentToken = token
    return this.getUserOrFail()
  }

  async generateWithRefreshToken(refreshToken?: string): Promise<JwtGenerateResult<true>> {
    this.authenticationAttempted = true

    if (!this.#driver.canSign) {
      throw new RuntimeException(
        'JWT guard cannot issue tokens in JWKS mode: tokens are issued by the identity provider'
      )
    }

    if (!this.#refreshTokenUserProvider) {
      throw new RuntimeException(REFRESH_TOKENS_NOT_CONFIGURED)
    }

    if (!refreshToken) {
      refreshToken = await this.#findRefreshToken()
    }

    const accessToken = await this.#refreshTokenUserProvider.verifyToken(new Secret(refreshToken))

    if (!accessToken) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    /**
     * When refresh token abilities are configured, reject tokens that
     * don't have all of them (e.g. an API token from another provider)
     */
    const requiredAbilities = this.#options.refreshTokenAbilities ?? []
    if (!requiredAbilities.every((ability) => accessToken.allows(ability))) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    /**
     * Fetch the user by user ID
     */
    const providerUser = await this.#refreshTokenUserProvider.findById(accessToken.tokenableId)
    if (!providerUser) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    /**
     * Delete the refresh token from the database. Only one of two concurrent
     * requests using the same refresh token can delete it
     */
    const isDeleted = await this.#refreshTokenUserProvider.invalidateToken(new Secret(refreshToken))
    if (!isDeleted) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    const user = providerUser.getOriginal() as UserProvider[typeof symbols.PROVIDER_REAL_USER] & {
      currentToken: string
    }
    const result = await this.generate(user)

    /**
     * Like after `authenticate()`, `currentToken` holds the access token
     * of the request, here the one that has just been issued
     */
    this.isAuthenticated = true
    this.user = user
    this.user.currentToken = result.token

    /**
     * The guard has a refresh token provider, so `generate()` issued a refresh token
     */
    return result as JwtGenerateResult<true>
  }

  async #findRefreshToken(): Promise<string> {
    /**
     * The cookie is the configured transport, so it takes precedence
     */
    if (this.#options.useCookiesForRefreshToken) {
      const cookieToken = this.#ctx.request.cookie(this.#refreshTokenName)
      if (cookieToken) {
        return cookieToken
      }
    }

    /**
     * Only read the request body: a refresh token passed in the
     * query string would end up in access logs and Referer headers
     */
    const bodyToken = this.#ctx.request.body()[this.#refreshTokenName]
    if (typeof bodyToken === 'string' && bodyToken) {
      return bodyToken
    }

    const authHeader = this.#ctx.request.header('authorization')
    if (authHeader) {
      if (authHeader.toLowerCase().startsWith('bearer ')) {
        const token = authHeader.slice(7).trim()
        if (token) {
          return token
        }
      }
    }

    throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: this.driverName,
    })
  }

  /**
   * Revoke the refresh token passed as argument, or else the one issued
   * during this request, or else the one sent by the client (cookie, body
   * or Authorization header).
   *
   * The cookies are always cleared. When no valid refresh token is found,
   * nothing is revoked and `E_UNAUTHORIZED_ACCESS` is raised, so a client
   * that sends the wrong token (e.g. its access token) does not believe it
   * has logged out while its refresh token stays valid.
   */
  async revoke(refreshToken?: string): Promise<void> {
    if (!this.#refreshTokenUserProvider) {
      throw new RuntimeException(REFRESH_TOKENS_NOT_CONFIGURED)
    }

    this.#clearCookies()

    refreshToken = refreshToken ?? this.#issuedRefreshToken ?? (await this.#findRefreshToken())

    /**
     * Only delete a refresh token whose secret is valid. The tokens
     * provider deletes by id alone, so a forged token with a guessed
     * id would otherwise revoke another user's refresh token.
     */
    const secret = new Secret(refreshToken)
    if (
      !(await this.#refreshTokenUserProvider.verifyToken(secret)) ||
      !(await this.#refreshTokenUserProvider.invalidateToken(secret))
    ) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    if (refreshToken === this.#issuedRefreshToken) this.#issuedRefreshToken = undefined
  }

  /**
   * Remove the access and refresh token cookies set by the guard
   */
  #clearCookies() {
    if (this.#options.useCookies) {
      this.#ctx.response.clearCookie(this.#tokenName, this.#cookieOptions)
    }

    if (this.#options.useCookiesForRefreshToken) {
      this.#ctx.response.clearCookie(this.#refreshTokenName, this.#cookieOptions)
    }
  }

  /**
   * Same as authenticate, but does not throw an exception
   */
  async check(): Promise<boolean> {
    try {
      await this.authenticate()
      return true
    } catch (error) {
      /**
       * Like the official guards, only an authentication failure means
       * "not logged in": a database outage must not look like a guest
       */
      if (error instanceof errors.E_UNAUTHORIZED_ACCESS) return false
      throw error
    }
  }

  /**
   * Returns the authenticated user or throws an error
   */
  getUserOrFail(): UserProvider[typeof symbols.PROVIDER_REAL_USER] & { currentToken: string } {
    if (!this.user) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    return this.user
  }

  /**
   * This method is called by Japa during testing when "loginAs"
   * method is used to login the user.
   */
  async authenticateAsClient(
    user: UserProvider[typeof symbols.PROVIDER_REAL_USER]
  ): Promise<AuthClientResponse> {
    const token: any = await this.generate(user)
    return {
      headers: {
        authorization: `Bearer ${token.token}`,
      },
    }
  }
}

const REFRESH_TOKENS_NOT_CONFIGURED =
  'JWT guard refresh tokens are not configured: set `refreshTokenUserProvider` in the guard config'

/**
 * The guard sets `exp`, and `iss` / `aud` when `issuer` / `audience` are
 * configured. jsonwebtoken refuses a payload that sets them too, with a
 * message about its own options (`options.expiresIn`) that the app never set.
 */
function assertNoGuardClaims(
  payload: Record<string, any>,
  options: { issuer?: string; audience?: string | string[] }
) {
  const conflicts: Array<[claim: string, option: string]> = [['exp', 'tokenExpiresIn']]
  if (options.issuer) conflicts.push(['iss', 'issuer'])
  if (options.audience) conflicts.push(['aud', 'audience'])

  for (const [claim, option] of conflicts) {
    if (payload[claim] !== undefined) {
      throw new RuntimeException(
        `JWT guard \`content\` must not set \`${claim}\`: the guard sets it from \`${option}\``
      )
    }
  }
}

function isUserId(value: unknown): value is string | number | bigint {
  return (
    (typeof value === 'string' && value !== '') ||
    (typeof value === 'number' && Number.isFinite(value)) ||
    typeof value === 'bigint'
  )
}
