import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

// We keep markdown source in the repository-root `docs/` tree so it stays
// pure and GitHub-readable, unmixed with build artefacts (see docs-site
// design §4). Starlight's built-in `docsLoader()` hard-codes the base path
// to `src/content/docs/`, and `starlight-links-validator` makes the same
// hard assumption when computing heading-table keys — it strips
// `<srcDir>/content/docs` from every markdown file path, and if that
// subtraction yields a non-clean path (because docs live elsewhere),
// every internal link is reported as invalid even though the pages render
// fine. Rather than diverge from the plugin's assumption, we expose the
// repo-root `docs/` tree under that conventional location via a symlink
// at `site/src/content/docs → ../../../docs`, and keep `docs/` in the
// repo root as the single source of truth. The symlink is checked in
// alongside the rest of the Starlight project.
//
// Starlight's default `docsLoader()` would work against that symlink, but
// we keep the explicit `glob()` loader so we can tweak the pattern. The
// `pattern` mirrors Starlight's default: recursive markdown variants,
// excluding files whose name starts with `_`. We additionally exclude:
//   - `internal/**`  — unpublished planning notes (internal docs, review, etc.)
//   - `README.md`    — GitHub-only landing; replaced by `index.md` once
//                      authored. Excluded now to avoid build failures if the
//                      file still exists at scaffold time.
// The published pages all live in subdirectories (`start/`, `guides/`,
// `concepts/`, `reference/`) or are the two root-level files we WANT to
// keep: `index.md` (the landing) and `404.md` (the custom 404 entry,
// required because our `description` extension makes Starlight's 404 stub
// fallback fail zod validation).
export const collections = {
  docs: defineCollection({
    loader: glob({
      base: './src/content/docs',
      pattern: [
        '**/*.{markdown,mdown,mkdn,mkd,mdwn,md,mdx}',
        '!**/_*',
        '!internal/**',
        '!README.md',
      ],
    }),
    // Extend Starlight's built-in schema to make `description` required on
    // every page. `title` is already required by `docsSchema()`. This
    // enforces the frontmatter minimum: every page needs a description.
    schema: docsSchema({
      extend: z.object({
        description: z.string(),
      }),
    }),
  }),
};
