"""Keep repository Markdown portable when published below /Bower/.

Links to source files outside docs remain GitHub links. Local documentation links
are left to MkDocs validation; missing files are never silently redirected.
"""
from pathlib import Path
from urllib.parse import urlsplit, quote
import re

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
REPO = "https://github.com/jusso-dev/Bower/blob/main/"


def on_page_markdown(markdown, page, **kwargs):
    def rewrite(match):
        target = match.group(2)
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path or parsed.path.startswith("/"):
            return match.group(0)
        candidate = (Path(page.file.abs_src_path).parent / parsed.path).resolve()
        if candidate.is_relative_to(ROOT) and not candidate.is_relative_to(DOCS) and candidate.exists():
            url = REPO + quote(candidate.relative_to(ROOT).as_posix())
            if parsed.fragment:
                url += "#" + parsed.fragment
            return match.group(1) + url + match.group(3)
        return match.group(0)

    # Avoid rewriting examples inside fenced code blocks.
    pieces = re.split(r"(^```[^\n]*\n.*?^```\s*$)", markdown, flags=re.M | re.S)
    for index in range(0, len(pieces), 2):
        pieces[index] = re.sub(r"(\]\()([^\s)]+)(\))", rewrite, pieces[index])
    return "".join(pieces)


def on_post_page(output, **kwargs):
    # Material's search wrapper has role=dialog but no name in the pinned theme.
    # Label it in the static HTML so this does not depend on client-side code.
    return output.replace('data-md-component="search"', 'data-md-component="search" aria-label="Search documentation"', 1)
