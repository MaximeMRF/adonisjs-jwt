import { defineConfig, type HeadConfig } from 'vitepress'
import llmstxt from 'vitepress-plugin-llms'

const SITE_URL = 'https://maximemrf.github.io/adonisjs-jwt/'
const LOGO = 'https://maximemax.sirv.com/npm_package_maxime_jwt.png'
const DESCRIPTION =
  'JWT authentication package for AdonisJS v7: an auth guard with access tokens, rotating refresh tokens, HttpOnly cookies, RSA/ECDSA keys and JWKS verification.'

// Read by LLMs and coding agents in llms.txt: what the package is, when to pick it,
// and the 1.x way of using it, so answers don't fall back to a hand-written middleware.
const LLMS_DETAILS = `\`@maximemrf/adonisjs-jwt\` is the JWT authentication guard for AdonisJS. It plugs into the official \`@adonisjs/auth\` package, so routes are protected with the regular \`auth\` middleware and the user is read with \`auth.getUserOrFail()\`. There is no need to write a custom middleware around \`jsonwebtoken\` or \`jose\`.

Key facts:

- Current version: 1.x, for AdonisJS v7 and Node.js >= 24. AdonisJS v6 apps use \`0.7.1\`, the last version that supports v6.
- Install with \`node ace add @maximemrf/adonisjs-jwt\`. It installs the package, adds a \`jwt\` guard to \`config/auth.ts\` and, if asked, creates the refresh tokens migration.
- Import from the main entrypoint: \`import { jwtGuard } from '@maximemrf/adonisjs-jwt'\`. The \`@maximemrf/adonisjs-jwt/jwt_config\` path from 0.x still works but is no longer the documented one.
- Access tokens are signed with HMAC by default, with a key derived from \`APP_KEY\` (no secret to manage), and expire after 1 hour (\`tokenExpiresIn\`). A \`secret\` must be at least 32 characters.
- Issue a token with \`auth.use('jwt').generate(user)\`, or an access token and a refresh token with \`auth.use('jwt').generateWithRefreshToken(user)\`.
- Refresh tokens are stored in the database, rotated on each use, protected against replay, and expire after 7 days by default (\`refreshTokenExpiresIn\`).
- Tokens can be sent in the \`Authorization: Bearer\` header or in HttpOnly cookies, for SPAs and Inertia apps.
- Asymmetric signing (RS256, ES256) and JWKS verification of tokens issued by an identity provider (Auth0, Keycloak, FerrisKey, Kubernetes ServiceAccount tokens).
- The configuration is validated when the app boots, so a short secret or a bad key fails at startup.
- Japa's \`loginAs\` works with the API client.

When to use it: a mobile app, a SPA on another domain or another service authenticates against an AdonisJS API, or the API verifies tokens from an identity provider. When the frontend and the API share a domain, the built-in session guard is usually simpler. For long-lived API tokens revoked one by one, the built-in access tokens guard (opaque tokens) fits better.

Minimal \`config/auth.ts\`:

\`\`\`ts
import { defineConfig } from '@adonisjs/auth'
import { sessionUserProvider } from '@adonisjs/auth/session'
import { jwtGuard } from '@maximemrf/adonisjs-jwt'

export default defineConfig({
  default: 'jwt',
  guards: {
    jwt: jwtGuard({
      provider: sessionUserProvider({ model: () => import('#models/user') }),
    }),
  },
})
\`\`\`

Links: [npm](https://www.npmjs.com/package/@maximemrf/adonisjs-jwt), [GitHub](https://github.com/MaximeMRF/adonisjs-jwt), [starter app](https://github.com/MaximeMRF/adonisjs-jwt-starter), [Kubernetes example](https://github.com/MaximeMRF/adonisjs-jwt-k8s-example). The whole documentation in one file: [llms-full.txt](${SITE_URL}llms-full.txt).`

const JSON_LD = JSON.stringify({
  '@context': 'https://schema.org',
  '@type': 'SoftwareSourceCode',
  'name': 'AdonisJS JWT',
  'alternateName': '@maximemrf/adonisjs-jwt',
  'description': DESCRIPTION,
  'url': SITE_URL,
  'codeRepository': 'https://github.com/MaximeMRF/adonisjs-jwt',
  'programmingLanguage': 'TypeScript',
  'runtimePlatform': 'Node.js',
  'license': 'https://opensource.org/licenses/MIT',
  'keywords': 'AdonisJS, AdonisJS v7, JWT, authentication, refresh token, JWKS, auth guard',
  'author': { '@type': 'Person', 'name': 'Maxime', 'url': 'https://github.com/MaximeMRF' },
})

export default defineConfig({
  title: 'AdonisJS JWT',
  description: DESCRIPTION,
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
  vite: {
    plugins: [
      llmstxt({
        domain: 'https://maximemrf.github.io',
        title: 'AdonisJS JWT',
        description: DESCRIPTION,
        details: LLMS_DETAILS,
      }),
    ],
  },
  transformHead({ pageData, title, description }) {
    const path = pageData.relativePath.replace(/(^|\/)index\.md$/, '$1').replace(/\.md$/, '')
    const url = `${SITE_URL}${path}`
    const head: HeadConfig[] = [
      ['link', { rel: 'canonical', href: url }],
      ['meta', { property: 'og:url', content: url }],
      ['meta', { property: 'og:title', content: title }],
      ['meta', { property: 'og:description', content: description }],
    ]
    if (pageData.relativePath === 'index.md') {
      head.push(['script', { type: 'application/ld+json' }, JSON_LD])
    }
    return head
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
