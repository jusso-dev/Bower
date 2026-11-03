"""The release version computation and the package downgrade guard."""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import version


REPO = Path(__file__).resolve().parents[2]
PREINSTALL = REPO / "deploy/installers/linux/scripts/preinstall.sh"


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

    def test_install_upgrade_and_same_version_reinstall_proceed(self):
        for installed in (None, "0.1.0-dev.361", "0.1.0-dev.362", "0.0.9"):
            with self.subTest(installed=installed):
                code, error, accounts = self.run_preinstall("0.1.0-dev.362", installed)
                self.assertEqual((code, error), (0, ""))
                self.assertTrue(accounts)


if __name__ == "__main__":
    unittest.main()
