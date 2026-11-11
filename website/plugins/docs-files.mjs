// Copies every non-Markdown file under docs/ (evidence reports, JSON, KQL, images) into the built
// site at the same path, as MkDocs did, so /Bower/evidence/<run>/report.html keeps working.
// research/ is not published, as before.
import { cp, readdir } from "node:fs/promises";
import path from "node:path";

const SKIP = new Set(["research"]);

async function copyTree(source, target) {
  for (const entry of await readdir(source, { withFileTypes: true })) {
    if (SKIP.has(entry.name) && source.endsWith("docs")) continue;
    const from = path.join(source, entry.name);
    const to = path.join(target, entry.name);
    if (entry.isDirectory()) await copyTree(from, to);
    else if (!/\.mdx?$/i.test(entry.name)) await cp(from, to, { force: true });
  }
}

export default function docsFiles(context) {
  return {
    name: "bower-docs-files",
    async postBuild({ outDir }) {
      await copyTree(path.resolve(context.siteDir, "../docs"), outDir);
    }
  };
}
