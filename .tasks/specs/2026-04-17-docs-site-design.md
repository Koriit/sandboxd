# sandboxd Documentation Site — Design

**Date:** 2026-04-17
**Status:** Approved
**Scope:** Stand up a published documentation site for sandboxd, and reshape existing docs around user journeys rather than reformatting them in place.

---

## 1 · Summary

- **Goal:** publish a proper documentation site for the sandboxd project, targeting developers who use the sandbox for coding-agent workflows.
- **Scope:** covers both the site infrastructure *and* a heavy content rewrite — we reshape around user journeys, not just reformat existing pages.
- **Primary user journey:** a developer lands on the docs and can install + run their first sandbox session within roughly 5 minutes.

## 2 · Technology choice

| Concern | Choice |
|---|---|
| Static site generator | Astro Starlight |
| Diagrams | Mermaid only (no PlantUML) |
| Hosting | GitHub Pages via Actions-as-source (modern; no `gh-pages` branch) |

**Rationale (brief).** Starlight wins on modern out-of-box polish, has the strongest landing-page story for quickstart-first framing, and satisfies our required features: left-side nav, right-side auto TOC, and Mermaid rendering.

**Alternatives considered and rejected:**

- **mkdocs-material** — weaker landing page; stronger PlantUML support, which we do not need.
- **Hugo** — theme-dependent polish; weaker customization.
- **mdBook** — weak landing page, no right-side TOC, dated feel.

## 3 · Site architecture — taxonomy and page map

Four top-level nav groups, ordered by user journey: `Start here`, `Guides`, `Concepts`, `Reference`.

Legend: ✦ = new page, ➜ = reworked from existing.

```
/                             ✦ landing — hero, value prop, 3 CTAs (Quickstart · Concepts · Reference)
/start/what-is-sandboxd/      ✦ one-pager — what it is, problems it solves, when to use
/start/quickstart/            ✦ 5-min: install → run first session → shell into it
/start/installation/          ➜ installation.md + lima-linux-install.md merged

/guides/first-real-session/   ✦ beyond quickstart — workspaces, policies, realistic flow
/guides/workspaces/           ➜ workspaces.md how-to half
/guides/network-policies/     ➜ policy.md as how-to
/guides/hardening/            ➜ hardening.md as how-to
/guides/integrate-agent/      ✦ plug into Claude Code / other agents / CI
/guides/troubleshooting/      ➜ troubleshooting.md

/concepts/sessions/           ✦ what a session is, lifecycle, persistence
/concepts/networking/         ➜ networking.md concept half
/concepts/workspaces/         ➜ workspaces.md concept half
/concepts/policy-model/       ➜ policy.md concept half
/concepts/architecture/       ➜ architecture.md + Mermaid diagram
/concepts/logging/            ➜ deployment-logging.md

/reference/cli/               ➜ cli-reference.md
/reference/http-api/          ✦ HTTP socket API (currently undocumented)
/reference/config/            ✦ daemon config reference
```

**Excluded from the published site:**

| File | Disposition |
|---|---|
| `session-plan.md` | Moved to `docs/internal/` |
| `plan-vs-implementation.md` | Moved to `docs/internal/` |
| `review-report.md` | Moved to `docs/internal/` |
| `docs/README.md` | Deleted — replaced by `docs/index.md` (the Starlight landing). GitHub's default file listing is sufficient when browsing `docs/` directly. The repo-root `README.md` is unaffected. |

## 4 · Repo layout

Content and site infrastructure are separated so `docs/` stays pure markdown (renders natively on GitHub; no build-file pollution):

```
docs/                     ← pure markdown, GitHub-readable, authored here
├── index.md              ← landing (Starlight hero via frontmatter)
├── start/
├── guides/
├── concepts/
├── reference/
└── internal/             ← unpublished planning docs

site/                     ← Astro Starlight project, consumes ../docs/
├── astro.config.mjs      ← content collection globs from ../docs/**/*.md
├── package.json
├── .nvmrc
├── public/               ← favicon, logo, og images (site chrome)
│   └── logo.svg          ← user-provided SVG; used as favicon + header logo
└── src/components/       ← custom components if needed
```

**Tradeoff.** Pointing an Astro content loader outside `src/` is slightly unconventional but supported. The benefit is that `docs/` stays pure content.

## 5 · Build and deploy pipeline

- **Local dev:** `make docs-dev` → `cd site && npm install && npm run dev`
- **Local build:** `make docs-build` → `cd site && npm install && npm run build`
- **GitHub Actions workflow** at `.github/workflows/docs.yml`:
  - Trigger: push to `main` touching `docs/**` or `site/**`.
  - Uses `actions/deploy-pages` (Actions-as-source; no `gh-pages` branch).
- **Node version** pinned via `.nvmrc` in `site/`.

## 6 · Quality gates (CI-enforced)

- `astro check` + `tsc` must pass.
- `starlight-links-validator` plugin fails the build on broken internal links.
- Frontmatter schema enforced by Starlight: `title` and `description` are required.

## 7 · Content plan — classification and phasing

Three buckets based on writing effort:

- ✦ **fresh** — no meaningful source to start from.
- ➜ **rewrite** — source exists but the content is reshaped materially (e.g. splitting a single page into concept + how-to halves).
- ➜light **light migration** — lift-and-shift with small edits for voice and frontmatter.

### 7.1 · Per-page classification

| Page | Source | Bucket |
|---|---|---|
| `/` (landing) | — | ✦ fresh |
| `start/what-is-sandboxd` | Repo-root `README.md` intro | ✦ fresh |
| `start/quickstart` | — | ✦ fresh |
| `start/installation` | `installation.md` + `lima-linux-install.md` | ➜light light migration |
| `guides/first-real-session` | — | ✦ fresh |
| `guides/workspaces` | `workspaces.md` (how-to half) | ➜ rewrite |
| `guides/network-policies` | `policy.md` (how-to half) | ➜ rewrite |
| `guides/hardening` | `hardening.md` | ➜ rewrite |
| `guides/integrate-agent` | — | ✦ fresh |
| `guides/troubleshooting` | `troubleshooting.md` | ➜light light migration |
| `concepts/sessions` | — | ✦ fresh |
| `concepts/networking` | `networking.md` (concept half) | ➜ rewrite |
| `concepts/workspaces` | `workspaces.md` (concept half) | ➜ rewrite |
| `concepts/policy-model` | `policy.md` (concept half) | ➜ rewrite |
| `concepts/architecture` | `architecture.md` | ➜light light migration + Mermaid |
| `concepts/logging` | `deployment-logging.md` | ➜light light migration |
| `reference/cli` | `cli-reference.md` | ➜light light migration |
| `reference/http-api` | — | ✦ fresh |
| `reference/config` | — | ✦ fresh |

Totals: **8 fresh, 6 rewrites, 5 light migrations = 19 pages.**

### 7.2 · Phasing

We split the work into two **sessions**. (Note: we deliberately call these "sessions" not "milestones" because the entire docs-site effort is itself a milestone in the broader project.)

**Session 1 — "Site is live and useful"**

- Site framework: Starlight project in `site/`, CI, GitHub Pages deploy, link-check plugin.
- Pages (7, including landing):
  - `/` landing
  - `start/what-is-sandboxd`
  - `start/quickstart`
  - `start/installation`
  - `concepts/architecture` (with one Mermaid diagram)
  - `reference/cli`
  - `guides/troubleshooting`
- Outcome: first-time visitors can install, run a session, and look up commands.

**Session 2 — "Docs are complete"**

- Remaining 12 pages:
  - 6 rewrites — the guide + concept splits of networking, workspaces, policy, and hardening.
  - `concepts/sessions`
  - `concepts/logging`
  - `guides/first-real-session`
  - `guides/integrate-agent`
  - `reference/http-api`
  - `reference/config`

## 8 · Writing conventions

- **Voice:** second person ("you"), present tense, imperative for steps.
- **Length:** keep pages short — if a page exceeds roughly 400 lines, split it.
- **Code samples:** real commands, copy-pasteable; prefer short complete examples over long annotated ones.
- **Frontmatter minimum:** `title` and `description` (drives search snippets and meta tags).
- **URLs:** kebab-case.

## 9 · Diagrams and assets

- **Mermaid** rendered at build time via `rehype-mermaid` (SVG output; no client-side JS).
- **Theme-aware:** two Mermaid themes registered; Starlight swaps them with dark/light mode.
- Diagrams are authored as fenced `` ```mermaid `` blocks inside plain `.md`, so GitHub still renders them natively.
- **Session 1 diagrams:** architecture diagram for `concepts/architecture`.
- **Session 2 diagrams:** networking flow (sequence) and session lifecycle (state).
- **Favicon and header logo:** single user-provided SVG, used as both the header logo and the favicon, referenced from `astro.config.mjs`.
  - Currently staged at `.tasks/specs/sandboxd-icon.svg`.
  - Moves to `site/public/logo.svg` during Session 1 implementation.
- **OG image:** static `site/public/og-image.png`, generated from the SVG later; not blocking.
- No project logo text beyond "sandboxd" in the header.

## 10 · Explicit out-of-scope

- **Versioning** — docs track `main` only; revisit when cutting a real release.
- **Internationalization** — English only.
- **Blog / changelog** — release notes stay in git/GitHub releases.
- **Auto-generated rustdoc** — the public Rust API is not the docs audience.
- **PR previews** — deferred.
- **Analytics** — none (no Plausible, GA, etc.).
- **Custom domain** — use the default `<user>.github.io/<repo>` URL.
- **Visual regression, accessibility audit, Lighthouse budget** — not in scope.
