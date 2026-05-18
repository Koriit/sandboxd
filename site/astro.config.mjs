// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';
import rehypeMermaid from 'rehype-mermaid';

// --- Mermaid strategy decision ---------------------------------------------
// Design spec §9 requires Mermaid diagrams to be rendered to SVG at build
// time (no client-side JS) and to swap with Starlight's dark/light toggle.
//
// rehype-mermaid offers four strategies:
//   * `inline-svg` (default)  — async, renders <svg> at build, needs a
//                               headless browser (Playwright/Chromium).
//   * `img-svg`               — async, renders SVG inside <img>; supports
//                               a built-in `dark` option that emits a
//                               <picture> element with responsive dark-mode
//                               sources. Needs Playwright/Chromium.
//   * `img-png`               — same, but PNG output. Needs Playwright.
//   * `pre-mermaid`           — synchronous; emits <pre class="mermaid">
//                               for the Mermaid JS library to render in the
//                               browser. NO Playwright needed, but violates
//                               the "no client-side JS" requirement.
//
// We pick `img-svg` with `dark: true` because it is the only strategy that
// produces SVGs at build time AND has native light/dark swapping that
// matches Starlight's theme toggle (via the <picture> element + CSS
// `prefers-color-scheme`). This does mean CI must install Playwright +
// Chromium; see the top-level docs CI workflow for that step.
//
// In `astro dev`, Playwright's per-request browser launch blanks the whole
// markdown body of any page containing a mermaid fence (silent failure that
// swallows the rest of the rehype output). We fall back to `pre-mermaid` in
// dev so iteration stays usable; builds keep `img-svg` for the published
// artifact. The dev-only client-side renderer is wired up below.
// ---------------------------------------------------------------------------

const isDev = process.argv[2] === 'dev';
const mermaidStrategy = isDev ? 'pre-mermaid' : 'img-svg';

// https://astro.build/config
export default defineConfig({
  // Published as a GitHub Pages project site at https://Koriit.github.io/sandboxd/.
  // Splitting origin (`site`) from path prefix (`base`) is the Astro idiom
  // for project-site deployments: Starlight's links-validator and built-in
  // route helpers both expect `base` to carry the subpath so internal links
  // resolve correctly under the `/sandboxd/` prefix.
  site: 'https://Koriit.github.io',
  base: '/sandboxd/',
  output: 'static',

  markdown: {
    // Starlight's default syntax highlighter (Shiki, via expressive-code for
    // code blocks) would otherwise treat ```mermaid fences as code to
    // highlight. Excluding `mermaid` here leaves the fenced block intact so
    // rehype-mermaid can pick it up during the rehype phase.
    syntaxHighlight: {
      type: 'shiki',
      excludeLangs: ['mermaid'],
    },
    rehypePlugins: [
      [
        rehypeMermaid,
        {
          strategy: mermaidStrategy,
          // Emits a <picture> element with both light and dark SVGs so the
          // diagram follows the user's color-scheme preference, which
          // Starlight's dark/light toggle drives. Only meaningful under
          // Playwright-based strategies; ignored for `pre-mermaid`.
          dark: true,
        },
      ],
    ],
  },

  integrations: [
    starlight({
      title: 'sandboxd',
      description:
        'Isolated, policy-controlled Linux VMs for coding agents, with per-session networking, TLS interception, and workspace provisioning.',
      logo: {
        src: './public/logo.svg',
        replacesTitle: false,
      },
      favicon: '/logo.svg',
      // In dev, rehype-mermaid runs under `pre-mermaid`, emitting raw <pre
      // class="mermaid"> blocks that expect a client-side Mermaid renderer.
      // Ship it from a CDN only in dev — builds render SVGs at the rehype
      // phase and need no client runtime.
      head: isDev
        ? [
            {
              tag: 'script',
              attrs: { type: 'module' },
              content:
                "import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs'; mermaid.initialize({ startOnLoad: true });",
            },
          ]
        : [],
      // Fail the build on broken internal links (spec §6, quality gates).
      plugins: [starlightLinksValidator()],
      // Taxonomy per spec §3: four top-level groups in this order.
      sidebar: [
        {
          label: 'Start here',
          items: [
            { label: 'What is sandboxd?', slug: 'start/what-is-sandboxd' },
            { label: 'Quickstart', slug: 'start/quickstart' },
            { label: 'Installation', slug: 'start/installation' },
          ],
        },
        {
          label: 'Guides',
          items: [
            { label: 'Your first real session', slug: 'guides/first-real-session' },
            { label: 'Workspaces', slug: 'guides/workspaces' },
            { label: 'Network policies', slug: 'guides/network-policies' },
            { label: 'Hardening', slug: 'guides/hardening' },
            { label: 'Lite mode', slug: 'guides/lite-mode' },
            { label: 'Integrate an agent', slug: 'guides/integrate-agent' },
            { label: 'Roll back an upgrade', slug: 'guides/rollback' },
            { label: 'Troubleshooting', slug: 'guides/troubleshooting' },
          ],
        },
        {
          label: 'Concepts',
          items: [
            { label: 'Sessions', slug: 'concepts/sessions' },
            { label: 'Networking', slug: 'concepts/networking' },
            { label: 'Workspaces', slug: 'concepts/workspaces' },
            { label: 'Policy model', slug: 'concepts/policy-model' },
            { label: 'Architecture', slug: 'concepts/architecture' },
            { label: 'Logging', slug: 'concepts/logging' },
          ],
        },
        {
          label: 'Operate',
          items: [
            { label: 'Update sandboxd', slug: 'operate/update' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'CLI reference', slug: 'reference/cli' },
            { label: 'HTTP API', slug: 'reference/http-api' },
            { label: 'Configuration', slug: 'reference/config' },
          ],
        },
      ],
    }),
  ],
});
