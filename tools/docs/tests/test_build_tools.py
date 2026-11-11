import importlib.util
import io
import json
import re
import shutil
import subprocess
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




class SidebarTests(unittest.TestCase):
    """Every published docs page is in the sidebars exactly once, and every sidebar id exists."""

    def test_every_page_is_in_the_sidebars_once(self):
        root = TOOLS.parents[1]
        docs = root / "docs"
        sidebars = (root / "website/sidebars.ts").read_text(encoding="utf-8")
        ids = re.findall(r'"id": "([^"]+)"', sidebars)
        pages = sorted(
            path.relative_to(docs).with_suffix("").as_posix()
            for path in docs.rglob("*")
            if path.suffix in (".md", ".mdx")
            and not path.relative_to(docs).as_posix().startswith(("research/", "evidence/"))
            and not path.name.startswith("_")
        )
        duplicates = sorted({page for page in ids if ids.count(page) > 1})
        self.assertEqual(duplicates, [], "pages listed twice in website/sidebars.ts")
        self.assertEqual(sorted(set(ids) - set(pages)), [], "sidebar ids with no page in docs/")
        # Published and linked from other pages, but not in the navigation (as on the MkDocs site).
        unlisted = {"deployment/native-sources", "operations/production-readiness"}
        self.assertEqual(sorted(set(pages) - set(ids) - unlisted), [], "pages missing from website/sidebars.ts")


class SourceLinkTests(unittest.TestCase):
    """website/plugins/remark-source-links.mjs, run with node."""

    def rewrite(self, url, source="docs/reference/index.md"):
        root = TOOLS.parents[1]
        script = (
            "import { rewrite } from './website/plugins/remark-source-links.mjs';"
            "console.log(rewrite(process.argv[1], process.argv[2]));"
        )
        result = subprocess.run(
            ["node", "--input-type=module", "-e", script, url, str(root / source)],
            cwd=root, capture_output=True, text=True, check=True)
        return result.stdout.strip()

    @unittest.skipUnless(shutil.which("node"), "node is not on PATH")
    def test_repository_files_become_github_links(self):
        self.assertEqual(self.rewrite("../../README.md#why-bower"),
                         "https://github.com/jusso-dev/Bower/blob/main/README.md#why-bower")

    @unittest.skipUnless(shutil.which("node"), "node is not on PATH")
    def test_docs_pages_and_missing_files_are_left_alone(self):
        self.assertEqual(self.rewrite("cli.md"), "cli.md")
        self.assertEqual(self.rewrite("../../missing-file.md"), "../../missing-file.md")
        self.assertEqual(self.rewrite("https://example.org/x"), "https://example.org/x")

    @unittest.skipUnless(shutil.which("node"), "node is not on PATH")
    def test_files_under_docs_link_to_their_published_copy(self):
        self.assertEqual(
            self.rewrite("../evidence/pilot-native-20261030/report.html", "docs/getting-started/index.md"),
            "pathname:///Bower/evidence/pilot-native-20261030/report.html")


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
