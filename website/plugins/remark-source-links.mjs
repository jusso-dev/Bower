// Links from a docs page to a repository file outside docs/ (source, deploy templates, examples)
// become GitHub links, as tools/docs/hooks.py did for MkDocs. Links inside docs/ are left to
// Docusaurus, which fails the build when a target is missing. A missing repository file is left
// as written, so the broken-link check reports it instead of hiding it behind a GitHub URL.
import { existsSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const DOCS = path.join(ROOT, "docs");
const REPO = "https://github.com/jusso-dev/Bower/blob/main/";

export function rewrite(url, sourceFile) {
  if (!url || /^[a-z][a-z0-9+.-]*:/i.test(url) || url.startsWith("//") || url.startsWith("/") || url.startsWith("#")) {
    return url;
  }
  const [pathPart, fragment] = url.split("#", 2);
  if (!pathPart) return url;
  const target = path.resolve(path.dirname(sourceFile), decodeURIComponent(pathPart));
  const insideRepo = target === ROOT || target.startsWith(ROOT + path.sep);
  const insideDocs = target === DOCS || target.startsWith(DOCS + path.sep);
  if (insideDocs) {
    // Evidence reports, JSON and other non-Markdown files under docs/ are copied to the same
    // path in the built site (plugins/docs-files.mjs), as MkDocs did; link to that path.
    if (!/\.mdx?$/i.test(target) && existsSync(target) && statSync(target).isFile()) {
      const relative = path.relative(DOCS, target).split(path.sep).map(encodeURIComponent).join("/");
      return "pathname:///Bower/" + relative + (fragment ? "#" + fragment : "");
    }
    return url;
  }
  if (!insideRepo || !existsSync(target)) return url;
  const relative = path.relative(ROOT, target).split(path.sep).map(encodeURIComponent).join("/");
  return REPO + relative + (fragment ? "#" + fragment : "");
}

function visit(node, fn) {
  fn(node);
  for (const child of node.children ?? []) visit(child, fn);
}

export default function remarkSourceLinks() {
  return (tree, file) => {
    const source = file.path ?? file.history?.[0];
    if (!source) return;
    visit(tree, (node) => {
      // Images stay with Docusaurus, which bundles them; only links are rewritten.
      if ((node.type === "link" || node.type === "definition") && typeof node.url === "string") {
        node.url = rewrite(node.url, source);
      }
    });
  };
}
