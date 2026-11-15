# Vigilante Documentation Site (`@vigilante/githubio`)

This is the static documentation portal for **Vigilante**, the autonomous cybersecurity orchestration, incident response, network reconnaissance, and CTF cyber range platform.

Built with Next.js (Turbopack), React 19, MDX, and Tailwind CSS. Search indexing is powered by Pagefind.

## Getting Started

From the monorepo root or `apps/githubio`:

```bash
pnpm --filter githubio dev
```

Open [http://localhost:3000](http://localhost:3000) to view the documentation portal.

## Production Build & Static Export

To build the static HTML export and generate the Pagefind search indexes:

```bash
pnpm --filter githubio build
```

The output artifacts are written to `apps/githubio/out/` and deployed to GitHub Pages via GitHub Actions.
