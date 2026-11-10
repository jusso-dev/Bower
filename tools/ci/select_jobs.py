"""Conservative CI selection, using local Git diffs without API file limits."""

import argparse
import os
from pathlib import Path
import subprocess


JOBS = ("dotnet", "infrastructure", "powershell", "ui", "e2e",
        "windows", "containers", "platforms", "packaging")

# Direct and transitive project references of lab/aws/upgrade-recovery/probe.
# Changes here must exercise the compiled evidence probe in the infrastructure job.
WEC_PROBE_PROJECTS = (
    "src/Bower.Persistence/", "src/Bower.Source.WindowsEventLog/", "src/Bower.Redaction/",
    "src/Bower.Abstractions/", "src/Bower.Contracts/",
)
WEC_POSITION_INPUTS = {
    "lab/aws/tests/test_wec_receiving_position.ps1",
    "lab/aws/soak/wec-agent.ps1",
    "lab/aws/wecfix/wec-agent.ps1",
}


def select(paths, full=False):
    selected = set(JOBS) if full else set()
    for path in paths:
        # The Windows steps of this guide are run as written by the monitoring-windows job (#246).
        if path == "docs/getting-started/aws-cloudwatch-agent.md":
            selected.add("infrastructure")
            continue
        # Known editorial inputs cannot affect product builds. Check this before
        # the unknown-file fallback, but never ignore Markdown under source/tests.
        if path.startswith(("docs/", "docs-site/", "tools/docs/")) or path in {
            "README.md", "LICENSE", "AGENTS.md", "CLAUDE.md", "mkdocs.yml",
            ".github/CODEOWNERS", ".github/pull_request_template.md",
            ".github/dependabot.yml", ".github/workflows/docs.yml",
        } or path.startswith(".github/ISSUE_TEMPLATE/"):
            continue
        if path.startswith((".github/workflows/", "tools/ci/")):
            selected.update(JOBS)
        elif path.startswith("lab/aws/packs/"):
            selected.update(("infrastructure", "dotnet"))
        elif path.startswith(("lab/aws/", "tests/scorecard/")):
            selected.add("infrastructure")
            if path in WEC_POSITION_INPUTS or path.startswith("lab/aws/upgrade-recovery/probe/"):
                selected.add("windows")
        elif path.startswith("ui/"):
            selected.update(("ui", "e2e"))
        elif path.startswith("powershell/"):
            selected.add("powershell")
        elif path.startswith(("deploy/installers/", "deploy/ansible/", "deploy/systemd/", "tests/installers/")):
            selected.update(("dotnet", "platforms", "packaging", "powershell"))
        elif path.startswith(("deploy/docker/", "tests/e2e/")) or path in {
            ".dockerignore", "docker-compose.yml", "compose.yml",
        }:
            selected.update(("dotnet", "ui", "containers"))
        elif path.startswith(("deploy/bicep/", "deploy/azure-function/", "deploy/sentinel/")):
            # C# contract tests check deployed Sentinel schemas, analytics content and function config.
            selected.update(("infrastructure", "dotnet"))
        elif path.startswith("deploy/"):
            selected.add("infrastructure")
        elif path.startswith("src/Bower.Output.Syslog/"):
            # The installer test runs this output under the packaged unit and journald (#245).
            selected.update(("dotnet", "windows", "e2e", "platforms", "packaging"))
        elif path.startswith(("src/", "tests/")):
            selected.update(("dotnet", "windows", "e2e"))
            if path.startswith(WEC_PROBE_PROJECTS):
                selected.add("infrastructure")
            if "/Relay/" in path or path.startswith("src/Bower.Forwarding/") or "Enrolment" in path:
                selected.add("containers")
        elif path.startswith(("packs/", "policies/", "schemas/")):
            selected.update(("dotnet", "powershell", "e2e"))
            if path.startswith("policies/default/"):
                selected.update(("platforms", "packaging"))
        else:
            # New tooling, global build settings and unrecognised paths fail safe.
            selected.update(JOBS)
    return {job: job in selected for job in JOBS}


def changed_paths(base, head, pull_request=False):
    comparison = f"{base}...{head}" if pull_request else f"{base}..{head}"
    # --no-renames includes both old and new paths, and -z handles odd filenames.
    result = subprocess.run(
        ["git", "diff", "--name-only", "--no-renames", "-z", comparison],
        check=True, stdout=subprocess.PIPE,
    )
    return [p for p in os.fsdecode(result.stdout).split("\0") if p]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--pull-request", action="store_true")
    parser.add_argument("--base")
    parser.add_argument("--head", default="HEAD")
    args = parser.parse_args()
    # Manual, scheduled, release-tag and initial pushes validate everything.
    full = args.full or not args.base or set(args.base) == {"0"}
    paths = [] if full else changed_paths(args.base, args.head, args.pull_request)
    result = select(paths, full)
    output = "".join(f"{job}={str(enabled).lower()}\n" for job, enabled in result.items())
    print(output, end="")
    if target := os.environ.get("GITHUB_OUTPUT"):
        with Path(target).open("a", encoding="utf-8") as stream:
            stream.write(output)


if __name__ == "__main__":
    main()
