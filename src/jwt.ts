import { symbols, errors } from '@adonisjs/auth'
import { AuthClientResponse, GuardContract } from '@adonisjs/auth/types'
import type { HttpContext } from '@adonisjs/core/http'
import jwt from 'jsonwebtoken'
import type { StringValue } from 'ms'
import { JwtUserProviderContract, JwtGuardOptions } from './types.js'
import { Secret } from '@adonisjs/core/helpers'
import { AccessTokensUserProviderContract } from '@adonisjs/auth/types/access_tokens'
import { JwksManager } from './jwks.js'

export class JwtGuard<
  UserProvider extends JwtUserProviderContract<unknown>,
> implements GuardContract<UserProvider[typeof symbols.PROVIDER_REAL_USER]> {
  #ctx: HttpContext
  #userProvider: UserProvider
  #refreshTokenUserProvider?: AccessTokensUserProviderContract<
    UserProvider[typeof symbols.PROVIDER_REAL_USER]
  >
  #options: JwtGuardOptions<UserProvider[typeof symbols.PROVIDER_REAL_USER]>
  #tokenName: string
  #refreshTokenName: string = 'refreshToken'
  #jwksManager?: JwksManager

  constructor(
    ctx: HttpContext,
    userProvider: UserProvider,
    option: JwtGuardOptions<UserProvider[typeof symbols.PROVIDER_REAL_USER]>
  ) {
    this.#ctx = ctx
    this.#userProvider = userProvider
    this.#options = option
    this.#refreshTokenUserProvider = this.#options.refreshTokenUserProvider
    if (!this.#options.content) this.#options.content = (user) => ({ userId: user.getId() })
    this.#tokenName = this.#options.tokenName ?? 'token'
    this.#jwksManager = this.#options.jwks ? new JwksManager(this.#options.jwks) : undefined
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
  async generate(user: UserProvider[typeof symbols.PROVIDER_REAL_USER]) {
    if (this.#options.jwks) {
      throw new errors.E_UNAUTHORIZED_ACCESS("You can't use the auth.generate method with jwks", {
        guardDriverName: this.driverName,
      })
    }
    const providerUser = await this.#userProvider.createUserForGuard(user)
    const token = jwt.sign(
      this.#options.content!(providerUser),
      this.#options.secret,
      this.#options.expiresIn
        ? {
            expiresIn: this.#options.expiresIn,
          }
        : {}
    )

    let refreshToken
    if (this.#refreshTokenUserProvider) {
      const generatedRefreshToken = await this.#refreshTokenUserProvider.createToken(
        user,
        this.#options.refreshTokenAbilities ?? [],
        this.#options.refreshTokenExpiresIn
          ? {
              expiresIn: this.#options.refreshTokenExpiresIn,
            }
          : undefined
      )
      refreshToken = generatedRefreshToken.value!.release()
    }

    if (this.#options.useCookies) {
      this.#ctx.response.cookie(`${this.#tokenName}`, token, {
        httpOnly: true,
      })
    }

    if (this.#options.useCookiesForRefreshToken && refreshToken) {
      this.#ctx.response.cookie(`${this.#refreshTokenName}`, refreshToken, {
        httpOnly: true,
      })
    }

    return {
      type: 'bearer',
      token: token,
      expiresIn: this.#options.expiresIn,
      refreshToken: refreshToken,
      refreshTokenExpiresIn: this.#options.refreshTokenExpiresIn,
    }
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

    const cookieHeader = this.#ctx.request.request.headers.cookie
    let token

    /**
     * If cookies are enabled, then read the token from the cookies
     */
    if (cookieHeader) {
      const regex = new RegExp(`${this.#tokenName}=([^;]*)`)
      token =
        this.#ctx.request.cookie(`${this.#tokenName}`) ??
        (this.#ctx.request.request.headers.cookie!.match(regex) || [])[1]
    }

    /**
     * If token is missing on cookies, then try to read it from the header authorization
     */
    if (!token) {
      /**
       * Ensure the auth header exists
       */
      const authHeader = this.#ctx.request.header('authorization')
      if (!authHeader) {
        throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
          guardDriverName: this.driverName,
        })
      }

      /**
       * Split the header value and read the token from it
       */
      ;[, token] = authHeader!.split('Bearer ')
      if (!token) {
        throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
          guardDriverName: this.driverName,
        })
      }
    }

    /**
     * Verify token
     */
    let payload

    try {
      if (this.#jwksManager) {
        const decoded = jwt.decode(token, { complete: true })
        if (!decoded || !decoded.header || !decoded.header.kid) {
          throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
            guardDriverName: this.driverName,
          })
        }
        const key = await this.#jwksManager.getSigningKey(decoded.header.kid)
        payload = jwt.verify(token, key)
      } else {
        payload = jwt.verify(token, this.#options.secret)
      }
    } catch {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    if (!payload || typeof payload !== 'object' || !('userId' in payload)) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    /**
     * Fetch the user by user ID and save a reference to it
     */
    const providerUser = await this.#userProvider.findById(
      (payload as { userId: string | number | BigInt }).userId
    )
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

  async generateWithRefreshToken(refreshToken?: string): Promise<
    | {
        type: string
        token: string
        expiresIn: number | StringValue | undefined
        refreshToken: string | undefined
        refreshTokenExpiresIn: number | StringValue | undefined
      }
    | undefined
  > {
    this.authenticationAttempted = true

    if (this.#options.jwks) {
      throw new errors.E_UNAUTHORIZED_ACCESS('JWKS is not supported for refresh token', {
        guardDriverName: this.driverName,
      })
    }

    if (!this.#refreshTokenUserProvider) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
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
     * Fetch the user by user ID
     */
    const providerUser = await this.#refreshTokenUserProvider.findById(accessToken.tokenableId)
    if (!providerUser) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    this.isAuthenticated = true
    this.user = providerUser.getOriginal() as UserProvider[typeof symbols.PROVIDER_REAL_USER] & {
      currentToken: string
    }

    /**
     * Delete the refresh token from the database
     */
    const isDeleted = await this.#refreshTokenUserProvider.invalidateToken(new Secret(refreshToken))
    if (!isDeleted) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    return this.generate(this.user)
  }

  async #findRefreshToken(): Promise<string> {
    const bodyToken = this.#ctx.request.input('refreshToken')
    if (bodyToken) {
      return bodyToken
    }

    if (this.#options.useCookiesForRefreshToken) {
      const cookieToken = this.#ctx.request.cookie(this.#refreshTokenName)
      if (cookieToken) {
        return cookieToken
      }
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
   * Revoke the refresh token
   */
  async revoke(refreshToken?: string) {
    if (!this.#refreshTokenUserProvider) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    if (!refreshToken) {
      try {
        refreshToken = await this.#findRefreshToken()
      } catch {
        return
      }
    }

    await this.#refreshTokenUserProvider.invalidateToken(new Secret(refreshToken))
  }

  /**
   * Same as authenticate, but does not throw an exception
   */
  async check(): Promise<boolean> {
    try {
      await this.authenticate()
      return true
    } catch {
      return false
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
