"""Serve the production build beneath the same project prefix as GitHub Pages."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[2]
if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="bower-docs-") as temporary:
        (Path(temporary) / "Bower").symlink_to(ROOT / "site", target_is_directory=True)
        handler = partial(SimpleHTTPRequestHandler, directory=temporary)
        ThreadingHTTPServer(("127.0.0.1", 50331), handler).serve_forever()
