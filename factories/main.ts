import { JwtUserProviderContract } from '../src/types.js'
import { symbols } from '@adonisjs/auth'
import jwt from 'jsonwebtoken'

export type JwtAuthFakeUser = {
  id: number
  email: string
  password: string
}

export const users: JwtAuthFakeUser[] = [
  {
    id: 1,
    email: 'maxou@max.com',
    password: 'secret',
  },
  {
    id: 2,
    email: 'max@max.com',
    password: 'secret',
  },
]

export class JwtFakeUserProvider implements JwtUserProviderContract<JwtAuthFakeUser> {
  declare [symbols.PROVIDER_REAL_USER]: JwtAuthFakeUser

  async createToken(
    user: JwtAuthFakeUser,
    secret: string,
    options?: { expiresIn?: string | number }
  ) {
    return jwt.sign({ userId: user.id }, secret, options)
  }

  /**
   * Creates the adapter user for the guard
   */
  async createUserForGuard(user: JwtAuthFakeUser) {
    return {
      getId() {
        return user.id
      },
      getOriginal() {
        return user
      },
    }
  }

  /**
   * Finds a user id
   */
  async findById(id: number) {
    const user = users.find(({ id: userId }) => userId === id)
    if (!user) {
      return null
    }

    return this.createUserForGuard(user)
  }
}
