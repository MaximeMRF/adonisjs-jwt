import { configPkg } from '@adonisjs/eslint-config'
export default configPkg({
  ignores: ['coverage', 'docs/.vitepress/cache', 'docs/.vitepress/dist'],
})
