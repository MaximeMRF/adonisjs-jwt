import { JwtUserProviderContract } from '../src/jwt.js'
import { symbols } from '@adonisjs/auth'

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
