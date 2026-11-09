#!/usr/bin/env python3
"""Build or check Bower's verified OWASP ASVS 5.0 and ASD ISM control lists.

Standard library only. The lists under docs/security/verified/ are the only ASVS and
ISM identifiers Bower content may cite (tests/Bower.UnitTests/ComplianceCitationTests.cs).

    # Rebuild from the official sources (network):
    python3 -I tools/compliance/verify_sources.py write
    # Re-download and fail if the committed lists drift from the sources:
    python3 -I tools/compliance/verify_sources.py check
    # Offline: use files you downloaded yourself (hashes are still checked):
    python3 -I tools/compliance/verify_sources.py check --asvs-json FILE --ism-json FILE

Downloads go to a fresh temporary directory and are parsed as data only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import tempfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "docs" / "security" / "verified"

ASVS_TAG = "v5.0.0_release"
ASVS_COMMIT = "5cf9b032440be53ce345ab3c130fda46ba1ce7a2"
ASVS_ASSET = "OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json"
ASVS_URL = f"https://github.com/OWASP/ASVS/releases/download/{ASVS_TAG}/{ASVS_ASSET}"
ASVS_SHA256 = "8201b20eec2908c3380ac600c91c8ba746346fbb808859366abb232027532311"
ASVS_CHAPTER_URL = (
    f"https://github.com/OWASP/ASVS/blob/{ASVS_COMMIT}/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md"
)
# Every V16 requirement plus the logging-relevant requirements in other chapters.
ASVS_OTHER = [
    "V2.4.1", "V4.1.3",
    "V6.1.1", "V6.3.1", "V6.3.5", "V6.3.7", "V6.4.3", "V6.4.6", "V6.5.6", "V6.6.3", "V6.6.4",
    "V7.2.4", "V7.4.1", "V7.4.2", "V7.4.3", "V7.4.5", "V7.5.1",
    "V8.2.1", "V8.2.2", "V8.2.3", "V8.3.2",
    "V13.4.5", "V14.1.2", "V14.2.4", "V15.3.4",
]

ISM_RELEASE = "v2026.09.4"
ISM_MONTH = "September 2026"
ISM_URL = f"https://www.cyber.gov.au/ism/oscal/{ISM_RELEASE}/artifacts/ISM_catalog.json"
ISM_SHA256 = "237ea09362b8449ed5c5ee85de4725a0468ee73d13af7cf61c26d4e6ac47f12d"
# Whole sections whose controls are all about event logging.
ISM_SECTIONS = [
    "Security monitoring policy",
    "Centralised event logging facility",
    "Event log details",
    "Event log monitoring",
    "Threat hunting",
    "Event log retention",
    "Software event logging",
    "Database event logging",
    "Operating system event logging",
    "Server application event logging",
    "Network device event logging",
]
# Single event logging controls in other sections, and controls other Bower docs cite.
ISM_OTHER = [
    "1509", "1650", "1683", "1895", "1566", "1613", "2139",
    "2051", "2052", "1910", "2015", "1536", "2159", "2125",
]


def fetch(url: str, directory: pathlib.Path) -> pathlib.Path:
    target = directory / url.rsplit("/", 1)[-1]
    request = urllib.request.Request(url, headers={"User-Agent": "bower-verify-sources"})
    with urllib.request.urlopen(request, timeout=120) as response, target.open("wb") as out:  # noqa: S310
        out.write(response.read())
    return target


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def asvs_list(path: pathlib.Path) -> dict:
    digest = sha256(path)
    if digest != ASVS_SHA256:
        raise SystemExit(f"ASVS asset hash {digest} is not the pinned {ASVS_SHA256}")
    rows = json.loads(path.read_text(encoding="utf-8"))["requirements"]
    by_id = {row["req_id"]: row for row in rows}
    wanted = [row["req_id"] for row in rows if row["chapter_id"] == "V16"] + ASVS_OTHER
    missing = [item for item in wanted if item not in by_id]
    if missing:
        raise SystemExit(f"Not in ASVS 5.0.0: {missing}")
    return {
        "standard": "OWASP Application Security Verification Standard",
        "version": "5.0.0",
        "source": {
            "repository": "https://github.com/OWASP/ASVS",
            "tag": ASVS_TAG,
            "commit": ASVS_COMMIT,
            "asset": ASVS_URL,
            "assetSha256": digest,
            "chapter": ASVS_CHAPTER_URL,
        },
        "requirements": [
            {
                "id": item,
                "level": int(by_id[item]["L"]),
                "chapter": f'{by_id[item]["chapter_id"]} {by_id[item]["chapter_name"]}',
                "section": f'{by_id[item]["section_id"]} {by_id[item]["section_name"]}',
                "text": by_id[item]["req_description"],
            }
            for item in wanted
        ],
    }


def _text(parts: list | None) -> str:
    out = []
    for part in parts or []:
        if part.get("prose"):
            out.append(part["prose"])
        nested = _text(part.get("parts"))
        if nested:
            out.append(nested)
    return "\n".join(out)


def ism_list(path: pathlib.Path) -> dict:
    digest = sha256(path)
    if digest != ISM_SHA256:
        raise SystemExit(f"ISM catalogue hash {digest} is not the pinned {ISM_SHA256}")
    catalog = json.loads(path.read_text(encoding="utf-8"))["catalog"]
    if catalog["metadata"]["version"] != ISM_RELEASE.removeprefix("v"):
        raise SystemExit(f'ISM catalogue version {catalog["metadata"]["version"]} is not {ISM_RELEASE}')
    controls = []

    def walk(group: dict, trail: list[str]) -> None:
        for child in group.get("groups", []):
            walk(child, trail + [child["title"]])
        for control in group.get("controls", []):
            props = {p["name"]: p["value"] for p in control.get("props", []) if "name" in p and "value" in p}
            controls.append((control["id"].removeprefix("ism-"), trail, props, _text(control.get("parts"))))

    for group in catalog["groups"]:
        walk(group, [group["title"]])
    by_id = {c[0]: c for c in controls}
    wanted = [c[0] for c in controls if c[1][-1] in ISM_SECTIONS]
    wanted += [item for item in ISM_OTHER if item not in wanted]
    missing = [item for item in wanted if item not in by_id]
    if missing:
        raise SystemExit(f"Not in ISM {ISM_RELEASE}: {missing}")
    return {
        "standard": "Information Security Manual (ISM)",
        "release": ISM_MONTH,
        "source": {
            "publisher": "Australian Signals Directorate",
            "page": f"https://www.cyber.gov.au/ism/oscal/{ISM_RELEASE}",
            "catalogue": ISM_URL,
            "catalogueVersion": catalog["metadata"]["version"],
            "catalogueSha256": digest,
        },
        "controls": [
            {
                "id": f"ISM-{item}",
                "revision": int(by_id[item][2].get("revision", "0")),
                "updated": by_id[item][2].get("updated"),
                "applicability": by_id[item][2].get("applicability"),
                "guideline": by_id[item][1][0],
                "section": " > ".join(by_id[item][1][1:]),
                "text": by_id[item][3],
            }
            for item in wanted
        ],
    }


def render(document: dict) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=["write", "check"])
    parser.add_argument("--asvs-json", type=pathlib.Path)
    parser.add_argument("--ism-json", type=pathlib.Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="bower-sources-") as temp:
        directory = pathlib.Path(temp)
        asvs = asvs_list(args.asvs_json or fetch(ASVS_URL, directory))
        ism = ism_list(args.ism_json or fetch(ISM_URL, directory))
    outputs = {OUT / "asvs-5.0.0-logging.json": render(asvs), OUT / "ism-2026-09-logging.json": render(ism)}
    if args.mode == "write":
        OUT.mkdir(parents=True, exist_ok=True)
        for path, text in outputs.items():
            path.write_text(text, encoding="utf-8")
        print(f"wrote {len(asvs['requirements'])} ASVS requirements and {len(ism['controls'])} ISM controls")
        return 0
    drift = [str(path.relative_to(ROOT)) for path, text in outputs.items()
             if not path.exists() or path.read_text(encoding="utf-8") != text]
    if drift:
        print("verified lists differ from the sources: " + ", ".join(drift), file=sys.stderr)
        return 1
    print(f"ok: {len(asvs['requirements'])} ASVS requirements, {len(ism['controls'])} ISM controls")
    return 0


if __name__ == "__main__":
    sys.exit(main())
