"""Check local links, assets and anchors in the built site using only the stdlib."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit
import sys


class Document(HTMLParser):
    def __init__(self, path):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.ids = set()
        self.feed(path.read_text(encoding="utf-8"))

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        for name in ("href", "src"):
            if attrs.get(name):
                self.links.append(attrs[name])


def check(root):
    root = root.resolve()
    documents = {path: Document(path) for path in root.rglob("*.html")}
    errors = []
    for path, document in documents.items():
        for link in document.links:
            parsed = urlsplit(link)
            if parsed.scheme or parsed.netloc:
                continue
            relative = unquote(parsed.path)
            if relative.startswith("/Bower/"):
                target = root / relative[len("/Bower/"):]
            elif relative.startswith("/"):
                errors.append(f"{path.relative_to(root)}: link escapes project base: {link}")
                continue
            else:
                target = path.parent / relative if relative else path
            target = target.resolve()
            if not target.is_relative_to(root):
                errors.append(f"{path.relative_to(root)}: link escapes site: {link}")
                continue
            if target.is_dir():
                target /= "index.html"
            if not target.exists():
                errors.append(f"{path.relative_to(root)}: missing target: {link}")
            elif parsed.fragment and target in documents and unquote(parsed.fragment) not in documents[target].ids:
                errors.append(f"{path.relative_to(root)}: missing anchor: {link}")
    for error in sorted(set(errors)):
        print(error)
    if errors:
        raise SystemExit(1)
    print(f"Checked local links and anchors in {len(documents)} HTML pages.")


if __name__ == "__main__":
    check(Path(sys.argv[1] if len(sys.argv) > 1 else "site"))
