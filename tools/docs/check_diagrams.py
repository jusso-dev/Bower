"""Check that every Mermaid block in docs/ is built as a diagram, not as a code listing.

An unknown fence language is not an error in `mkdocs build --strict`, so without the
`mermaid` custom fence in mkdocs.yml the diagrams silently become highlighted source text.
Usage: check_diagrams.py SITE_DIR [DOCS_DIR]. Stdlib only.
"""
from html.parser import HTMLParser
from pathlib import Path
import re
import sys

FENCE = re.compile(r"^\s*```+\s*mermaid\s*$", re.MULTILINE)


class Diagrams(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.count = 0
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        classes = (dict(attrs).get("class") or "").split()
        if "mermaid" in classes and tag != "code":
            self.count += 1


def built_page(site, docs, source):
    """The HTML file MkDocs writes for a Markdown file with use_directory_urls: true."""
    relative = source.relative_to(docs).with_suffix("")
    if relative.name in ("index", "README"):
        return site / relative.parent / "index.html"
    return site / relative / "index.html"


def check(site, docs):
    errors = []
    checked = 0
    for source in sorted(docs.rglob("*.md")):
        expected = len(FENCE.findall(source.read_text(encoding="utf-8")))
        if not expected:
            continue
        page = built_page(site, docs, source)
        if not page.is_file():
            continue  # excluded from the site (exclude_docs); the link check covers the nav
        checked += 1
        found = Diagrams(page.read_text(encoding="utf-8")).count
        if found != expected:
            errors.append(f"{source.relative_to(docs)}: {expected} mermaid block(s), {found} diagram element(s) in {page.relative_to(site)}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        raise SystemExit(1)
    print(f"Checked Mermaid diagrams on {checked} pages.")
    return checked


if __name__ == "__main__":
    site_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "site")
    docs_dir = Path(sys.argv[2] if len(sys.argv) > 2 else "docs")
    check(site_dir, docs_dir)
