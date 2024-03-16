import type { ApplicationService } from '@adonisjs/core/types'
import { jwtGuard } from '../src/define_config.js'

export default class JwtProvider {
  constructor(protected app: ApplicationService) {}
  register() {
    this.app.container.singleton('max/jwt', async () => {
      return jwtGuard
    })
  }
}

declare module '@adonisjs/core/types' {
  interface ContainerBindings {
    'max/jwt': typeof jwtGuard
  }
}
