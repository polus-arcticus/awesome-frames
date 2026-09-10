# `docs`

The [awesome-frames](https://github.com/polus-arcticus/awesome-frames) documentation site, built with [Docusaurus](https://docusaurus.io/). Content lives in `docs/`; see the [root README](../../README.md) for the rest of the monorepo.

## Local development

```bash
pnpm docs:start
```

Starts a local dev server with live reload. Or, from this directory directly:

```bash
pnpm start
```

## Build

```bash
pnpm docs:build
```

Generates static content into `build/`, servable by any static host.

## Deployment

Deploys to GitHub Pages (`polus-arcticus/awesome-frames`, `gh-pages` branch — see `organizationName`/`projectName`/`deploymentBranch` in `docusaurus.config.ts`):

```bash
GIT_USER=<your GitHub username> pnpm deploy
```

Or, with SSH:

```bash
USE_SSH=true pnpm deploy
```
