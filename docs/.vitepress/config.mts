import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'AdonisJS JWT',
  description: 'Authenticate AdonisJS users with JWT access tokens and refresh tokens',
  base: '/adonisjs-jwt/',
  lang: 'en-US',
  cleanUrls: true,
  lastUpdated: true,
  head: [['link', { rel: 'icon', href: 'https://maximemax.sirv.com/npm_package_maxime_jwt.png' }]],
  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/introduction' },
      { text: 'Reference', link: '/reference/options' },
      { text: 'Upgrading to 1.0', link: '/upgrading/1.0' },
    ],
    sidebar: [
      {
        text: 'Getting started',
        items: [
          { text: 'Introduction', link: '/guide/introduction' },
          { text: 'Installation', link: '/guide/installation' },
          { text: 'Configuration', link: '/guide/configuration' },
          { text: 'Authentication', link: '/guide/authentication' },
        ],
      },
      {
        text: 'Guides',
        items: [
          { text: 'Refresh tokens', link: '/guide/refresh-tokens' },
          { text: 'Cookies and token transport', link: '/guide/token-transport' },
          { text: 'Asymmetric signing', link: '/guide/asymmetric' },
          { text: 'JWKS', link: '/guide/jwks' },
          { text: 'Kubernetes ServiceAccount tokens', link: '/guide/kubernetes' },
          { text: 'Testing', link: '/guide/testing' },
          { text: 'Security', link: '/guide/security' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'Options', link: '/reference/options' },
          { text: 'Guard API', link: '/reference/guard' },
        ],
      },
      {
        text: 'Upgrading',
        items: [{ text: 'Upgrading to 1.0', link: '/upgrading/1.0' }],
      },
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/MaximeMRF/adonisjs-jwt' },
      { icon: 'npm', link: 'https://www.npmjs.com/package/@maximemrf/adonisjs-jwt' },
    ],
    editLink: {
      pattern: 'https://github.com/MaximeMRF/adonisjs-jwt/edit/main/docs/:path',
    },
    search: { provider: 'local' },
    footer: {
      message: 'Released under the MIT License.',
    },
  },
})
