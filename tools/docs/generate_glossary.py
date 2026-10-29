"""Generate the user glossary from the same definitions used by the console."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "ui/Bower.Management.Web/src/components/glossary.json"
TARGET = ROOT / "docs/getting-started/concepts.md"


def render():
    entries = json.loads(SOURCE.read_text(encoding="utf-8"))
    lines = ["# Concepts and glossary", "", "The same plain-English definitions appear in the Bower console's Help page.", "",
             "## The event path", "", "**Collect → Select → Arrange → Deliver → Prove.** Collect security events, select",
             "what policy allows, structure and redact before persistence, deliver with",
             "acknowledgement, then verify a canary with a destination query.", ""]
    for entry in entries:
        lines.extend([f"## {entry['term']} {{#{entry['id']}}}", "", entry["definition"], ""])
    lines.extend(["## Default deny", "", "Unknown events are rejected by policy unless an approved rule explicitly allows them.", "",
                  "## Source", "", "The application, host or cloud service that produces a security event.", "",
                  "## Evidence", "", "A record of a test result. Query-verified evidence means Sentinel returned the exact",
                  "test event. Simulated evidence is labelled simulated and is not proof of delivery.", ""])
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render()
    if args.check:
        if not TARGET.exists() or TARGET.read_text(encoding="utf-8") != expected:
            raise SystemExit("Glossary is stale. Run python tools/docs/generate_glossary.py and commit the result.")
    else:
        TARGET.write_text(expected, encoding="utf-8")
