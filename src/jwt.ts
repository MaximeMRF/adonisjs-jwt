import { symbols, errors } from '@adonisjs/auth'
import { AuthClientResponse, GuardContract } from '@adonisjs/auth/types'
import type { HttpContext } from '@adonisjs/core/http'
import jwt from 'jsonwebtoken'

/**
 * The bridge between the User provider and the
 * Guard
 */
export type JwtGuardUser<RealUser> = {
  /**
   * Returns the unique ID of the user
   */
  getId(): string | number | BigInt

  /**
   * Returns the original user object
   */
  getOriginal(): RealUser
}

/**
 * The interface for the UserProvider accepted by the
 * JWT guard.
 */
export interface JwtUserProviderContract<RealUser> {
  /**
   * A property the guard implementation can use to infer
   * the data type of the actual user (aka RealUser)
   */
  [symbols.PROVIDER_REAL_USER]: RealUser

  /**
   * Create a user object that acts as an adapter between
   * the guard and real user value.
   */
  createUserForGuard(user: RealUser): Promise<JwtGuardUser<RealUser>>

  /**
   * Find a user by their id.
   */
  findById(identifier: string | number | BigInt): Promise<JwtGuardUser<RealUser> | null>
}

export type JwtGuardOptions = {
  secret: string
  expiresIn?: number | string
  useCookies?: boolean
}

export class JwtGuard<UserProvider extends JwtUserProviderContract<unknown>>
  implements GuardContract<UserProvider[typeof symbols.PROVIDER_REAL_USER]>
{
  #ctx: HttpContext
  #userProvider: UserProvider
  #options: JwtGuardOptions

  constructor(ctx: HttpContext, userProvider: UserProvider, option: JwtGuardOptions) {
    this.#ctx = ctx
    this.#userProvider = userProvider
    this.#options = option
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
  user?: UserProvider[typeof symbols.PROVIDER_REAL_USER]

  /**
   * Generate a JWT token for a given user.
   */
  async generate(user: UserProvider[typeof symbols.PROVIDER_REAL_USER]) {
    const providerUser = await this.#userProvider.createUserForGuard(user)
    const token = jwt.sign(
      { userId: providerUser.getId() },
      this.#options.secret,
      this.#options.expiresIn
        ? {
            expiresIn: this.#options.expiresIn,
          }
        : {}
    )

    if (this.#options.useCookies) {
      return this.#ctx.response.cookie('token', token, {
        httpOnly: true,
      })
    }

    return {
      type: 'bearer',
      token: token,
      expiresIn: this.#options.expiresIn,
    }
  }

  /**
   * Authenticate the current HTTP request and return
   * the user instance if there is a valid JWT token
   * or throw an exception
   */
  async authenticate(): Promise<UserProvider[typeof symbols.PROVIDER_REAL_USER]> {
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
      token = this.#ctx.request.cookie('token')
        ? this.#ctx.request.cookie('token')
        : (this.#ctx.request.request.headers.cookie!.match(/token=(.*?)(;|$)/) || [])[1]
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
      payload = jwt.verify(token, this.#options.secret)
    } catch (error) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    if (typeof payload !== 'object' || !('userId' in payload)) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    /**
     * Fetch the user by user ID and save a reference to it
     */
    const providerUser = await this.#userProvider.findById(payload.userId)
    if (!providerUser) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    this.isAuthenticated = true
    this.user = providerUser.getOriginal()
    return this.getUserOrFail()
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
  getUserOrFail(): UserProvider[typeof symbols.PROVIDER_REAL_USER] {
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
        authorization: `Bearer ${this.#options.useCookies ? token : token.token}`,
      },
    }
  }
}
