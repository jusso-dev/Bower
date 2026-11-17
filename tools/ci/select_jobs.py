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
# Inputs to tests/e2e/aws-emulator.sh, which runs in the containers job.
AWS_EMULATOR_INPUTS = (
    "deploy/aws/bower-aws-security.yaml", "deploy/aws/bower-s3-output.yaml",
    "packs/aws-security/", "tests/fixtures/aws-emulator/",
    "src/Bower.Agent.Cloud/", "src/Bower.Source.Aws/", "src/Bower.Output.S3/",
)
WEC_POSITION_INPUTS = {
    "lab/aws/tests/test_wec_receiving_position.ps1",
    "lab/aws/soak/wec-agent.ps1",
    "lab/aws/wecfix/wec-agent.ps1",
}
# The native binaries the publish job ships. Locked-mode restore fails when a package
# change reaches either closure without regenerating its lock file, so these two lock
# files are the signal that a package bump changes what the platform matrix builds.
NATIVE_LOCK_FILES = {
    "src/Bower.Cli/packages.lock.json",
    "src/Bower.Collector/packages.lock.json",
}
# The unit tests read these: ComplianceCitationTests checks every ASVS/ISM citation under
# them, CliHelpTests docs/reference/cli.md, IntegrityAndDcrTests docs/reference/sentinel-table.md.
DOC_CONTRACT_INPUTS = ("docs/", "tools/docs/", "tools/compliance/")
DOC_CONTRACT_FILES = {"README.md", "PRODUCT.md", "SECURITY.md"}
# Workflows the CI jobs never run: each is linted by workflow-lint and runs on its own.
SEPARATE_WORKFLOWS = {
    ".github/workflows/docs.yml", ".github/workflows/images.yml",
    ".github/workflows/asvs-examples.yml",
}


def select(paths, full=False):
    selected = set(JOBS) if full else set()
    for path in paths:
        # The Windows steps of this guide are run as written by the monitoring-windows job (#246).
        if path == "docs/getting-started/aws-cloudwatch-agent.md":
            selected.update(("infrastructure", "dotnet"))
            continue
        # The Documentation workflow builds the site; build-test runs the doc contract tests.
        if path.startswith(DOC_CONTRACT_INPUTS) or path in DOC_CONTRACT_FILES:
            selected.add("dotnet")
            continue
        # Known editorial inputs that nothing builds, tests or packages. Check this
        # before the unknown-file fallback, but never ignore Markdown under source/tests.
        if path.startswith(("website/", "plans/", "reports/", ".github/ISSUE_TEMPLATE/")) or path in {
            "LICENSE", "AGENTS.md", "CLAUDE.md", "CONTRIBUTING.md", "DESIGN.md", ".gitignore",
            ".github/CODEOWNERS", ".github/pull_request_template.md", ".github/dependabot.yml",
        } or path in SEPARATE_WORKFLOWS:
            continue
        if path.startswith((".github/workflows/", "tools/ci/")):
            selected.update(JOBS)
        elif path == "Directory.Packages.props":
            # Every .NET build restores in locked mode, so a version change that reaches the
            # native binaries also changes NATIVE_LOCK_FILES (which add the platform matrix).
            selected.update(set(JOBS) - {"platforms", "packaging"})
        elif path in NATIVE_LOCK_FILES:
            selected.update(("dotnet", "windows", "e2e", "platforms", "packaging"))
        elif path.startswith(("rules/", "tools/queue-migration-check/")):
            # Sigma rules are unit-test content; the migration check is a unit-test reference.
            selected.update(("dotnet", "windows", "e2e"))
        elif path.startswith("examples/"):
            # Unit tests read the contracts and quick starts; the minimal API is in Bower.sln;
            # the infrastructure jobs run the cloud agent quick starts (#226, #246).
            selected.update(("dotnet", "infrastructure"))
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
            if path.startswith(AWS_EMULATOR_INPUTS):
                selected.add("containers")
        elif path.startswith("src/Bower.Output.AmaSyslog/"):
            # The installer test runs this output under the packaged unit and journald (#245).
            selected.update(("dotnet", "windows", "e2e", "platforms", "packaging"))
        elif path.startswith(("src/", "tests/")):
            selected.update(("dotnet", "windows", "e2e"))
            if path.startswith(WEC_PROBE_PROJECTS):
                selected.add("infrastructure")
            if ("/Relay/" in path or path.startswith("src/Bower.Forwarding/") or "Enrolment" in path
                    or path.startswith(AWS_EMULATOR_INPUTS)):
                selected.add("containers")
        elif path.startswith(("packs/", "policies/", "schemas/")):
            selected.update(("dotnet", "powershell", "e2e"))
            if path.startswith("policies/default/"):
                selected.update(("platforms", "packaging"))
            if path.startswith(AWS_EMULATOR_INPUTS):
                selected.add("containers")
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
