import importlib.util
import io
import json
import runpy
from unittest.mock import patch
from pathlib import Path
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1]

def load(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class LinkCheckTests(unittest.TestCase):
    def test_project_prefix_and_anchor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "index.html").write_text('<a href="/Bower/guide/#target">Guide</a>')
            (root / "guide").mkdir()
            (root / "guide/index.html").write_text('<h1 id="target">Guide</h1>')
            load("check_links").check(root)

    def test_bad_links_and_anchors_fail(self):
        for target in ('missing/', '#missing', '/wrong-base/', '../../escape'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "index.html").write_text(f'<a href="{target}">Broken</a>')
                with self.assertRaises(SystemExit):
                    load("check_links").check(root)

    def test_search_dialog_has_a_static_name(self):
        output = load("hooks").on_post_page('<div data-md-component="search" role="dialog"></div>')
        self.assertIn('aria-label="Search documentation"', output)

    def test_source_links_rewrite_but_missing_docs_and_code_do_not(self):
        hooks = load("hooks")
        class File:
            abs_src_path = str(hooks.DOCS / "reference/index.md")
        class Page:
            file = File()
        source = '[Source](../../README.md)\n[Missing](missing.md)\n```md\n[Example](../../README.md)\n```'
        output = hooks.on_page_markdown(source, Page())
        self.assertIn('[Source](https://github.com/jusso-dev/Bower/blob/main/README.md)', output)
        self.assertIn('[Missing](missing.md)', output)
        self.assertIn('```md\n[Example](../../README.md)\n```', output)

class GlossaryEncodingTests(unittest.TestCase):
    def test_generation_and_stale_check_with_a_legacy_default_encoding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "tools/docs/generate_glossary.py"
            source = root / "ui/Bower.Management.Web/src/components/glossary.json"
            target = root / "docs/getting-started/concepts.md"
            for path in (script, source, target):
                path.parent.mkdir(parents=True, exist_ok=True)
            script.write_bytes((TOOLS / "generate_glossary.py").read_bytes())
            source.write_text(json.dumps([{
                "id": "example", "term": "Café", "definition": "Résumé → evidence"
            }], ensure_ascii=False), encoding="utf-8")
            real_open = io.open

            def legacy_open(file, mode="r", buffering=-1, encoding=None, errors=None,
                            newline=None, closefd=True, opener=None):
                if "b" not in mode and encoding in (None, "locale"):
                    encoding = "cp1252"
                return real_open(file, mode, buffering, encoding=encoding, errors=errors,
                                 newline=newline, closefd=closefd, opener=opener)

            with patch("io.open", side_effect=legacy_open):
                with patch("sys.argv", [str(script)]):
                    runpy.run_path(str(script), run_name="__main__")
                self.assertIn("Résumé → evidence", target.read_text(encoding="utf-8"))
                with patch("sys.argv", [str(script), "--check"]):
                    runpy.run_path(str(script), run_name="__main__")
                    target.write_text("stale", encoding="utf-8")
                    with self.assertRaisesRegex(SystemExit, "Glossary is stale"):
                        runpy.run_path(str(script), run_name="__main__")

if __name__ == "__main__":
    unittest.main()
