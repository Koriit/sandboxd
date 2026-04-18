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
// If in the future we want to avoid Playwright in CI, the choice is between
// `pre-mermaid` (client-side JS, violates §9) or pre-rendering SVGs out of
// band and committing them. Either is a spec change.
// ---------------------------------------------------------------------------

// https://astro.build/config
export default defineConfig({
  // Published URL is assigned by GitHub Pages once the repo goes live.
  // TODO(m9-s16+): set the real URL after the repo slug is known, and pair
  // it with a matching `base:` if the site is served from a subpath
  // (GitHub project Pages). Until then we use a path-less placeholder so
  // Starlight's links-validator doesn't flag every internal link as
  // invalid for missing a non-existent base prefix.
  site: 'https://example.github.io',
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
          strategy: 'img-svg',
          // Emits a <picture> element with both light and dark SVGs so the
          // diagram follows the user's color-scheme preference, which
          // Starlight's dark/light toggle drives.
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
            { label: 'Integrate an agent', slug: 'guides/integrate-agent' },
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
