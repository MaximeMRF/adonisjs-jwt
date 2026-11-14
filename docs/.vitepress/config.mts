import { defineConfig } from 'vitepress'

const SITE_URL = 'https://maximemrf.github.io/adonisjs-jwt/'
const LOGO = 'https://maximemax.sirv.com/npm_package_maxime_jwt.png'

export default defineConfig({
  title: 'AdonisJS JWT',
  description: 'Authenticate AdonisJS users with JWT access tokens and refresh tokens',
  base: '/adonisjs-jwt/',
  lang: 'en-US',
  cleanUrls: true,
  lastUpdated: true,
  head: [
    ['link', { rel: 'icon', href: LOGO }],
    ['meta', { name: 'google-site-verification', content: 'iGJLU2YYnXWaSPIt0dSrR1pwZ96tTmCcg2vZ21lfI50' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:site_name', content: 'AdonisJS JWT' }],
    ['meta', { property: 'og:image', content: LOGO }],
    ['meta', { name: 'twitter:card', content: 'summary' }],
  ],
  sitemap: { hostname: SITE_URL },
  transformHead({ pageData, title, description }) {
    const path = pageData.relativePath.replace(/(^|\/)index\.md$/, '$1').replace(/\.md$/, '')
    const url = `${SITE_URL}${path}`
    return [
      ['link', { rel: 'canonical', href: url }],
      ['meta', { property: 'og:url', content: url }],
      ['meta', { property: 'og:title', content: title }],
      ['meta', { property: 'og:description', content: description }],
    ]
  },
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
          { text: 'Single-page apps', link: '/guide/spa' },
          { text: 'Inertia and server-rendered apps', link: '/guide/inertia' },
          { text: 'Asymmetric signing', link: '/guide/asymmetric' },
          { text: 'JWKS', link: '/guide/jwks' },
          { text: 'FerrisKey', link: '/guide/ferriskey' },
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
