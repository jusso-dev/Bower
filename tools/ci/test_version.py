"""The release version computation and the package downgrade guard."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import version


REPO = Path(__file__).resolve().parents[2]
PREINSTALL = REPO / "deploy/installers/linux/scripts/preinstall.sh"
# Without GITHUB_OUTPUT, so a CLI run in a test never writes to the job's outputs.
CLEAN_ENV = {key: value for key, value in os.environ.items() if key != "GITHUB_OUTPUT"}


class VersionTests(unittest.TestCase):
    def test_repository_version_file_is_a_release_core(self):
        core = version.read_core(REPO / "VERSION")
        self.assertRegex(core, r"^\d+\.\d+\.\d+$")

    def test_rust_workspace_version_matches_the_version_file(self):
        cargo = (REPO / "rust/Cargo.toml").read_text(encoding="utf-8")
        workspace = re.search(r'\[workspace\.package\]\s*\nversion = "([^"]+)"', cargo)
        self.assertEqual(version.read_core(REPO / "VERSION"), workspace.group(1))

    def test_branch_builds_are_dev_prereleases_numbered_by_the_build(self):
        result = version.compute("0.2.0", "branch", "main", 362)
        self.assertEqual(result["version"], "0.2.0-dev.362")
        self.assertEqual(result["build"], "362")
        self.assertEqual(result["prerelease"], "true")
        self.assertEqual(result["msi_version"], "0.2.362")

    def test_release_tag_must_match_the_version_file(self):
        result = version.compute("0.2.0", "tag", "v0.2.0", 400)
        self.assertEqual((result["version"], result["prerelease"], result["msi_version"]),
                         ("0.2.0", "false", "0.2.400"))
        self.assertEqual(version.compute("0.2.0", "tag", "v0.2.0-rc.1", 401)["version"], "0.2.0-rc.1")
        for tag in ("v0.2.1", "v0.1.9", "0.2.0", "v0.2.0-dev.5", "v0.2.0-beta.1", "v0.2.0+build"):
            with self.subTest(tag=tag), self.assertRaises(version.VersionError):
                version.compute("0.2.0", "tag", tag, 400)

    def test_development_builds_fail_once_the_version_is_released(self):
        with self.assertRaisesRegex(version.VersionError, "already released: bump VERSION"):
            version.compute("0.2.0", "branch", "main", 500, released=True)
        # The release tag build itself, and builds before the tag, still work.
        self.assertEqual(version.compute("0.2.0", "tag", "v0.2.0", 500, released=True)["version"], "0.2.0")
        self.assertEqual(version.compute("0.2.0", "branch", "main", 500)["version"], "0.2.0-dev.500")

    def test_check_released_reads_the_git_tags(self):
        with tempfile.TemporaryDirectory() as directory:
            def git(*args):
                subprocess.run(["git", *args], cwd=directory, check=True, capture_output=True)
            git("init", "-q")
            git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "x")
            Path(directory, "VERSION").write_text("0.2.0\n", encoding="utf-8")
            command = [sys.executable, str(Path(version.__file__).resolve()), "--version-file", "VERSION",
                       "--build-number", "7", "--check-released"]
            ok = subprocess.run(command, cwd=directory, capture_output=True, text=True, env=CLEAN_ENV)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            git("tag", "v0.2.0-rc.1")
            self.assertEqual(subprocess.run(command, cwd=directory, capture_output=True, env=CLEAN_ENV).returncode, 0)
            git("tag", "v0.2.0")
            refused = subprocess.run(command, cwd=directory, capture_output=True, text=True, env=CLEAN_ENV)
            self.assertEqual(refused.returncode, 2)
            self.assertIn("v0.2.0 is already released", refused.stderr)

    def test_build_number_fits_the_msi_build_field(self):
        for number in (-1, 65536):
            with self.subTest(number=number), self.assertRaises(version.VersionError):
                version.compute("0.2.0", "branch", "main", number)
        self.assertEqual(version.compute("0.2.0", "branch", "main", 65535)["msi_version"], "0.2.65535")
        # Unnumbered: a local build, a manually published image, the CI upgrade-test package.
        self.assertEqual(version.compute("0.2.0", "branch", "main", 0)["version"], "0.2.0-dev.0")

    def test_parse_accepts_only_the_bower_scheme(self):
        self.assertEqual(version.parse("1.2.3"), (1, 2, 3, 2, 0))
        self.assertEqual(version.parse("1.2.3-rc.4"), (1, 2, 3, 1, 4))
        self.assertEqual(version.parse("1.2.3-dev.0"), (1, 2, 3, 0, 0))
        for value in ("1.2", "1.2.3.4", "01.2.3", "1.2.3-dev", "1.2.3-dev.01", "1.2.3-alpha.1",
                      "1.2.3+sha", "256.0.0", "0.256.0", "1.2.3-dev.65536", " 1.2.3", "v1.2.3"):
            with self.subTest(value=value), self.assertRaises(version.VersionError):
                version.parse(value)

    def test_version_file_must_hold_only_a_core(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "VERSION"
            for content in ("0.2.0-dev.1\n", "0.2\n", "", "v0.2.0\n"):
                path.write_text(content, encoding="utf-8")
                with self.subTest(content=content), self.assertRaises(version.VersionError):
                    version.read_core(path)
            path.write_text("0.2.0\n", encoding="utf-8")
            self.assertEqual(version.read_core(path), "0.2.0")


class VersionKeyTests(unittest.TestCase):
    """The Windows MSI decides downgrades by comparing version keys as text."""

    ORDERED = ["0.1.0-dev.0", "0.1.0-dev.9", "0.1.0-dev.10", "0.1.0-dev.65535", "0.1.0-rc.1",
               "0.1.0-rc.10", "0.1.0", "0.1.1-dev.1", "0.1.1", "0.1.10-dev.1", "0.2.0-rc.1",
               "0.2.0-dev.401", "0.2.0", "0.10.0", "1.0.0", "255.255.65535"]

    def test_text_order_of_keys_is_semantic_version_order(self):
        semantic = sorted(self.ORDERED, key=version.parse)
        self.assertEqual(sorted(self.ORDERED, key=version.key), semantic)
        self.assertEqual(version.key("0.2.0-rc.1"), "000.002.00000.1.00001")

    def test_cross_stage_and_cross_patch_cases_from_review(self):
        # rc then a later dev build: MSI 0.2.400 -> 0.2.401 looks like an upgrade, but is not.
        rc = version.compute("0.2.0", "tag", "v0.2.0-rc.1", 400)
        dev = version.compute("0.2.0", "branch", "main", 401)
        self.assertLess(int(rc["msi_version"].split(".")[2]), int(dev["msi_version"].split(".")[2]))
        self.assertGreater(rc["version_key"], dev["version_key"])
        # An older patch rebuilt later than a newer patch.
        later_old_patch = version.compute("0.2.0", "tag", "v0.2.0", 600)
        newer_patch = version.compute("0.2.1", "tag", "v0.2.1", 500)
        self.assertGreater(newer_patch["version_key"], later_old_patch["version_key"])

    def test_build_ps1_computes_the_same_key(self):
        pwsh = shutil.which("pwsh")
        if not pwsh:
            self.skipTest("pwsh is not installed")
        script = REPO / "deploy/installers/windows/build.ps1"
        command = (
            "$ast = [System.Management.Automation.Language.Parser]::ParseFile($env:BUILD_SCRIPT, [ref]$null, [ref]$null);"
            "$f = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]"
            " -and $n.Name -eq 'Get-BowerVersionKey' }, $true);"
            ". ([scriptblock]::Create($f.Extent.Text));"
            "$env:VERSIONS.Split(' ') | ForEach-Object { Get-BowerVersionKey -Value $_ }")
        environment = {**os.environ, "BUILD_SCRIPT": str(script), "VERSIONS": " ".join(self.ORDERED)}
        result = subprocess.run([pwsh, "-NoProfile", "-NonInteractive", "-Command", command], env=environment,
                                capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.split(), [version.key(value) for value in self.ORDERED])


class ImageTagTests(unittest.TestCase):
    """images.yml moves :latest only for a final release tag."""

    def tags(self, ref_type, ref_name):
        # Dry run of the images.yml metadata: docker/metadata-action applies type=semver
        # {{major}}.{{minor}} to releases only, and adds latest when the flavor says so.
        result = version.compute("0.2.0", ref_type, ref_name, 0)
        tags = ["sha-5b7ded8"]
        if ref_type == "tag":
            tags.append(result["version"])
            if result["prerelease"] == "false":
                tags.append("0.2")
        if result["latest"] == "true":
            tags.append("latest")
        return tags

    def test_rc_tags_never_move_latest(self):
        self.assertEqual(self.tags("tag", "v0.2.0-rc.1"), ["sha-5b7ded8", "0.2.0-rc.1"])
        self.assertEqual(self.tags("tag", "v0.2.0"), ["sha-5b7ded8", "0.2.0", "0.2", "latest"])
        self.assertEqual(self.tags("branch", "main"), ["sha-5b7ded8"])

    def test_images_workflow_uses_the_computed_latest_flag(self):
        workflow = (REPO / ".github/workflows/images.yml").read_text(encoding="utf-8")
        self.assertIn("latest=${{ steps.version.outputs.latest }}", workflow)
        self.assertNotIn("latest=${{ startsWith(", workflow)
        self.assertIn("--build-number 0", workflow)


class PackageDowngradeGuardTests(unittest.TestCase):
    """The rendered preinstall script, with its account commands faked."""

    def functions(self):
        text = PREINSTALL.read_text(encoding="utf-8")
        start = text.index("# begin version functions")
        return text[start:text.index("# end version functions")]

    def older(self, left, right):
        result = subprocess.run(["sh", "-c", self.functions() + 'version_older "$1" "$2"', "sh", left, right],
                                check=False)
        return result.returncode == 0

    def test_version_order_matches_the_release_scheme(self):
        ordered = ["0.1.0-dev.0", "0.1.0-dev.9", "0.1.0-dev.10", "0.1.0-dev.362", "0.1.0-rc.1",
                   "0.1.0-rc.2", "0.1.0", "0.1.1-dev.1", "0.1.1", "0.2.0", "0.10.0", "1.0.0-dev.1", "1.0.0"]
        for index, left in enumerate(ordered):
            for other, right in enumerate(ordered):
                with self.subTest(left=left, right=right):
                    self.assertEqual(self.older(left, right), index < other)
                    self.assertEqual(version.parse(left) < version.parse(right), index < other)

    # Strings at and around every rule of the grammar (version.py is the reference).
    GRAMMAR_CASES = [
        "0.0.0", "0.1.0", "255.255.65535", "0.1.0-dev.0", "0.1.0-dev.65535", "0.1.0-rc.1",
        "00.1.0-dev.362", "0.01.0", "0.1.00", "0.1.0-dev.01", "0.1.0-rc.65536", "0.1.65536",
        "256.0.0", "0.256.0", "999999999.0.0", "0.1.0-rc.1-dev.2", "0.1.0-dev-rc.1",
        "0.1.0-dev.1.2", "0.1.0-dev", "0.1.0-dev.", "0.1.0-", "0.1.0-beta.1", "0.1.0+sha",
        "0.1", "0.1.0.0", ".1.0", "0..0", "-0.1.0", "v0.1.0", " 0.1.0", "0.1.0 ", "", "garbage",
        "0.1.0-DEV.1", "0.1.0-dev.+1", "0.1.0-dev.-1", "1e3.0.0", "0x1.0.0", "9" * 80]

    def valid_in_shell(self, value):
        result = subprocess.run(["sh", "-c", self.functions() + 'version_fields "$1" >/dev/null', "sh", value],
                                check=False)
        return result.returncode == 0

    def test_shell_grammar_matches_version_py(self):
        for value in self.GRAMMAR_CASES:
            with self.subTest(value=value):
                try:
                    version.parse(value)
                    expected = True
                except version.VersionError:
                    expected = False
                self.assertEqual(self.valid_in_shell(value), expected)

    def test_unrecognised_versions_are_never_older(self):
        for left, right in (("garbage", "0.1.0"), ("0.1.0", "garbage"), ("0.1", "0.2.0"),
                            ("0.1.0-beta.1", "0.2.0"), ("0.1.0-dev.", "0.2.0"), ("", "0.1.0"),
                            ("0.1.0-dev.1x", "0.2.0"), ("1234567890.0.0", "1.0.0")):
            with self.subTest(left=left, right=right):
                self.assertFalse(self.older(left, right))

    def run_preinstall(self, package_version, installed_version, allow=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = PREINSTALL.read_text(encoding="utf-8").replace("${BOWER_VERSION}", package_version)
            installed = root / "version"
            script = script.replace("/usr/share/bower/version", str(installed))
            (root / "preinstall.sh").write_text(script, encoding="utf-8")
            if installed_version is not None:
                installed.write_text(installed_version + "\n", encoding="utf-8")
            for name in ("getent", "groupadd", "useradd"):
                command = root / name
                command.write_text("#!/bin/sh\necho \"$0\" >> \"$TEST_LOG\"\nexit 0\n", encoding="utf-8")
                command.chmod(0o700)
            environment = {"PATH": f"{root}:/usr/bin:/bin", "TEST_LOG": str(root / "log")}
            if allow is not None:
                environment["BOWER_ALLOW_DOWNGRADE"] = allow
            result = subprocess.run(["sh", str(root / "preinstall.sh"), "upgrade"], env=environment,
                                    capture_output=True, text=True, check=False)
            accounts = (root / "log").exists()
            return result.returncode, result.stderr, accounts

    def test_downgrade_is_refused_before_anything_changes(self):
        code, error, accounts = self.run_preinstall("0.1.0-dev.0", "0.1.0-dev.362")
        self.assertEqual(code, 1)
        self.assertIn("refusing to downgrade from 0.1.0-dev.362 to 0.1.0-dev.0", error)
        self.assertIn("BOWER_ALLOW_DOWNGRADE=1", error)
        self.assertFalse(accounts)

    def test_downgrade_is_allowed_only_with_the_explicit_override(self):
        self.assertEqual(self.run_preinstall("0.1.0-dev.0", "0.1.0-dev.362", allow="true")[0], 1)
        code, error, accounts = self.run_preinstall("0.1.0-dev.0", "0.1.0-dev.362", allow="1")
        self.assertEqual(code, 0)
        self.assertIn("downgrading from 0.1.0-dev.362 to 0.1.0-dev.0", error)
        self.assertTrue(accounts)

    def test_unparseable_installed_marker_fails_closed(self):
        # Including near misses reported in review: leading zeros, limits, double suffixes.
        for marker in ("garbage", "", "0.1", "0.1.0-beta.1", "9" * 80, "00.1.0-dev.362",
                       "0.1.0-rc.65536", "999999999.0.0", "0.1.0-rc.1-dev.2", "0.1.0-dev-rc.1",
                       "256.0.0", "0.1.0-dev.01", "0.1.65536"):
            with self.subTest(marker=marker):
                code, error, accounts = self.run_preinstall("0.1.0-dev.362", marker)
                self.assertEqual(code, 1)
                self.assertIn("does not hold a Bower version", error)
                self.assertIn("BOWER_ALLOW_DOWNGRADE=1", error)
                self.assertFalse(accounts)
        for marker in ("00.1.0-dev.362", "0.1.0-rc.65536"):
            with self.subTest(package="0.1.1-dev.362", marker=marker):
                code, _, accounts = self.run_preinstall("0.1.1-dev.362", marker)
                self.assertEqual((code, accounts), (1, False))
        code, error, accounts = self.run_preinstall("0.1.0-dev.362", "garbage", allow="1")
        self.assertEqual(code, 0)
        self.assertIn("over an unrecognised installed version", error)
        self.assertTrue(accounts)

    def test_install_upgrade_and_same_version_reinstall_proceed(self):
        for installed in (None, "0.1.0-dev.361", "0.1.0-dev.362", "0.0.9", "0.0.65535", "0.1.0-dev.0"):
            with self.subTest(installed=installed):
                code, error, accounts = self.run_preinstall("0.1.0-dev.362", installed)
                self.assertEqual((code, error), (0, ""))
                self.assertTrue(accounts)



class LinuxBuildVersionLimitTests(unittest.TestCase):
    """build.sh accepts exactly the versions version.py accepts."""

    def build(self, value):
        with tempfile.TemporaryDirectory() as directory:
            return subprocess.run(
                ["bash", str(REPO / "deploy/installers/linux/build.sh"), directory, "amd64", value,
                 str(Path(directory) / "out")], cwd=REPO, capture_output=True, text=True, check=False)

    def test_out_of_range_versions_are_rejected_before_packaging(self):
        for value in ("256.0.0", "0.256.0", "0.1.65536", "0.1.1-dev.65536", "0.1.1-rc.70000",
                      "01.1.1", "0.1.1-beta.1", "0.1.1+sha"):
            with self.subTest(value=value):
                result = self.build(value)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("version must be MAJOR.MINOR.PATCH", result.stderr)
                with self.assertRaises(version.VersionError):
                    version.parse(value)

    def test_versions_at_the_limits_pass_the_check(self):
        for value in ("255.255.65535", "0.1.1-dev.65535", "0.1.1-rc.0", "0.1.1"):
            with self.subTest(value=value):
                version.parse(value)
                # Past the version check, the empty artefact folder is reported instead.
                result = self.build(value)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("missing", result.stderr)


if __name__ == "__main__":
    unittest.main()
