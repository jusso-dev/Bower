# Documentation site

## Decision: MkDocs Material on GitHub Pages

Bower's documentation stays in the repository's existing `docs/` Markdown files.
MkDocs Material builds static HTML with local search, responsive navigation and
light/dark appearance. A local homepage template adds a product introduction,
animated dataflow and links into task-oriented guides.

MkDocs fits the existing content and requires less maintenance than a separate
React/MDX application. Docusaurus was considered; its interactive component model
is unnecessary for this site's small, dependency-free illustration.

The homepage uses Bower's blue identity and self-hosted Geist font. Layout variation
is moderate (5/10), motion is explanatory (4/10), and density is restrained (4/10).
The actual console screenshot uses the existing synthetic preview dataset.

Material currently announces end of life on 5 May 2027. The pinned dependency is
build-time only; it is not a hosted application service. Evaluate its maintained
successor or another generator before that date. Markdown, local assets and the
small template are kept separate to make migration possible.

## Build locally

From the repository root:

```sh
uv venv .venv-docs
uv pip install --python .venv-docs/bin/python --require-hashes -r tools/docs/requirements.txt
.venv-docs/bin/python tools/docs/generate_glossary.py --check
.venv-docs/bin/mkdocs build --strict
.venv-docs/bin/python tools/docs/check_links.py site
.venv-docs/bin/mkdocs serve
```

The glossary is generated from the console's typed glossary data. After editing
that data, run `python tools/docs/generate_glossary.py` and commit the updated page.
The build verifies that it is current. Documentation links to repository files
outside `docs/` are converted to GitHub source links by `tools/docs/hooks.py`.
Missing documentation targets still fail validation.

## Publish

The documentation workflow builds and tests pull requests. After merge to `main`,
it uploads the static site and deploys to GitHub Pages using the `github-pages`
environment and GitHub's short-lived deployment identity. It never deploys from a
pull request. The repository must have Pages configured with **GitHub Actions** as
the build source.

The project URL is <https://jusso-dev.github.io/Bower/>. All asset and navigation
links support the `/Bower/` base path. No custom domain is required.

## Privacy and motion

There are no third-party analytics, remote fonts or external help widgets. The
illustration makes no network calls and contains no customer data. The animated
packets are explanatory and never represent live delivery or verified evidence.
A pause control and `prefers-reduced-motion` support make motion optional.

## Remaining documentation work

This site establishes publishing, navigation, the guided start and access to the
existing technical library. Issue #139 also tracks generated CLI/API/configuration
reference, scheduled external-link checks, release screenshot refresh automation,
docs-required policy, spelling checks, more source/deployment guides and real-user
validation. Those requirements are not claimed complete by the initial site.
