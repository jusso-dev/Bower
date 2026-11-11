# Documentation site

## Decision: Docusaurus on GitHub Pages

The Markdown stays where it was, in `docs/`. Docusaurus, in `website/`, builds it into a
static site with a React homepage, a tour of the console with screenshots in both
appearances, local search, and Mermaid diagrams. It replaced MkDocs Material in
November 2026: Material had announced end of life on 5 May 2027, and the homepage and
gallery wanted components that a Markdown template does not give.

What carried over unchanged:

- Every page address. The site is still served at `/Bower/` with the same paths, including
  the numbered production-readiness pages, and every evidence file under `docs/evidence/` is
  copied to the same path (`website/plugins/docs-files.mjs`). A browser test fetches a sample
  of old addresses.
- The navigation: `website/sidebars.ts` is the old MkDocs nav, section for section. A unit
  test fails if a page in `docs/` is missing from it or listed twice.
- Links to repository files outside `docs/` become GitHub links, as before
  (`website/plugins/remark-source-links.mjs`, with unit tests).
- The generated pages (glossary and CLI reference) and their staleness checks.
- The palette: dark navy and signal blue from the README artwork, amber details from the
  console, and the self-hosted Geist font.

Plain `.md` pages are read as CommonMark (`markdown.format: "detect"`), not MDX, so shell
snippets, KQL and JSON with braces and angle brackets need no escaping. A page that wants
components is written as `.mdx`, as the console tour is.

## Layout

| Path | What it is |
| --- | --- |
| `docs/` | The Markdown. Edit pages here. |
| `website/docusaurus.config.ts` | Site settings: base URL, navbar, footer, search, code themes. |
| `website/sidebars.ts` | Navigation, one sidebar per top-level section. |
| `website/src/pages/index.tsx` | The homepage. Every claim on it comes from the README or a docs page. |
| `website/src/components/` | The console gallery and the themed `Screenshot` used in `.mdx` pages. |
| `website/static/img/console/` | Console screenshots, `<page>-light.png` and `<page>-dark.png`. |
| `website/plugins/` | The source-link rewrite and the copy of non-Markdown files. |
| `tools/docs/` | Generators, the link check, unit tests and the browser tests. |

## Build locally

From the repository root:

```sh
uv venv .venv-docs
uv pip install --python .venv-docs/bin/python --require-hashes -r tools/docs/requirements.txt
.venv-docs/bin/python tools/docs/generate_glossary.py --check
.venv-docs/bin/python tools/docs/generate_cli_reference.py --check
.venv-docs/bin/python -m unittest discover -s tools/docs/tests -p 'test_*.py'

cd website
npm ci
npm start            # live preview at http://localhost:3000/Bower/
npm run build        # fails on any broken link, anchor, Markdown link or image
cd ..
.venv-docs/bin/python tools/docs/check_links.py website/build

cd tools/docs && npm ci && npx playwright install chromium && npm test
```

The glossary is generated from the console's typed glossary data. After editing that data,
run `python tools/docs/generate_glossary.py` and commit the updated page.

## Refresh the console screenshots

The screenshots use the console's synthetic preview dataset and its local development
sign-in, never a real tenant. Start the management API in development mode with the
console built in (as the `management-ui` CI job does, see the [README](../../README.md)),
seed it, then capture every page in both appearances:

```sh
cd ui/Bower.Management.Web
npm run seed:preview
BOWER_UI_BASE_URL=http://127.0.0.1:4320 npx playwright test e2e/docs-gallery.spec.ts --project=readme-chromium
```

This writes `website/static/img/console/<page>-light.png` and `-dark.png`. Review the images
before committing them: they should show only the preview collectors (`finance-prod-01`,
`claims-prod-03`, `records-prod-04`, `hr-legacy-02`).

## Publish

The documentation workflow builds and tests pull requests. After merge to `main`, it uploads
`website/build` and deploys to GitHub Pages using the `github-pages` environment and GitHub's
short-lived deployment identity. It never deploys from a pull request. The repository must
have Pages configured with **GitHub Actions** as the build source.

The project URL is <https://jusso-dev.github.io/Bower/>. No custom domain is required.

## Privacy

There are no third-party analytics, remote fonts, external help widgets or hosted search.
The search index is built with the site and searched in the browser. Mermaid is bundled
with the site and drawn in the browser; nothing is fetched from a CDN. A browser test
records every request while loading the homepage, the console tour and a page with a
diagram, and fails if any goes to another origin.

With JavaScript off, every page still reads: the text, tables, code and images are in the
static HTML. Diagrams and search need JavaScript.

## Checks

| Check | Where |
| --- | --- |
| Broken links, anchors, Markdown links and images | `npm run build` (Docusaurus fails the build) |
| Links and anchors in the built HTML | `tools/docs/check_links.py` |
| Every page in the sidebars once | `tools/docs/tests/test_build_tools.py` |
| Source links rewrite correctly | `tools/docs/tests/test_build_tools.py` |
| Accessibility (axe) on 17 pages, light and dark | `tools/docs/tests/site.spec.js` |
| Every Mermaid block drawn as a diagram | `tools/docs/tests/site.spec.js` |
| Search local, no request to another origin | `tools/docs/tests/site.spec.js` |
| 320 px fit, no-JavaScript reading, gallery keyboard use | `tools/docs/tests/site.spec.js` |
| Every console screenshot present in both themes | `tools/docs/tests/site.spec.js` |
| Old addresses and evidence files still resolve | `tools/docs/tests/site.spec.js` |

## Remaining documentation work

Issue #139 also tracks generated API and configuration reference, scheduled external-link
checks, refreshing screenshots at release, a docs-required policy, spelling checks and
real-user validation. The screenshot capture is scripted but not yet run by CI.
