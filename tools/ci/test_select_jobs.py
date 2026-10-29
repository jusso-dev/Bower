import os
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from select_jobs import JOBS, changed_paths, select


class SelectionTests(unittest.TestCase):
    def enabled(self, paths, **kwargs):
        return {job for job, enabled in select(paths, **kwargs).items() if enabled}

    def test_editorial_changes_do_not_build_product(self):
        self.assertEqual(set(), self.enabled([
            "docs/getting-started/index.md", "docs-site/stylesheets/extra.css",
            "tools/docs/check_links.py", "README.md", "mkdocs.yml",
        ]))

    def test_ui_runs_browser_tests_without_platform_matrix(self):
        self.assertEqual({"ui", "e2e"}, self.enabled(["ui/Bower.Management.Web/src/App.tsx"]))

    def test_source_security_changes_keep_tests_and_windows_coverage(self):
        self.assertEqual({"dotnet", "windows", "e2e"}, self.enabled([
            "src/Bower.Redaction/Redactor.cs", "tests/Bower.UnitTests/QueueTests.cs",
        ]))

    def test_shared_assets_test_both_implementations(self):
        result = self.enabled(["packs/windows-security-logon/parsers/security-4625.json"])
        self.assertTrue({"dotnet", "rust", "powershell", "e2e"} <= result)

    def test_default_policy_changes_validate_installers(self):
        self.assertTrue({"platforms", "packaging"} <= self.enabled(["policies/default/policy.json"]))

    def test_installer_changes_have_all_artifacts_and_install_checks(self):
        for path in ("deploy/installers/windows/build.ps1", "deploy/systemd/bower.service",
                     "tests/installers/linux.sh", "deploy/ansible/roles/bower/tasks/main.yml"):
            with self.subTest(path=path):
                self.assertTrue({"dotnet", "platforms", "packaging", "powershell"} <= self.enabled([path]))

    def test_relay_and_enrolment_keep_container_integration(self):
        for path in ("src/Bower.Collector/Relay/Listener.cs", "src/Bower.Forwarding/Client.cs",
                     "rust/crates/bower-collector/src/relay/output.rs", "tests/e2e/enrolment.sh"):
            with self.subTest(path=path):
                self.assertIn("containers", self.enabled([path]))

    def test_docker_changes_test_cross_architecture_builds(self):
        for path in ("deploy/docker/Dockerfile", "rust/Dockerfile", ".dockerignore", "docker-compose.yml"):
            self.assertIn("containers", self.enabled([path]))

    def test_aws_lab_checks_do_not_build_platforms(self):
        self.assertEqual({"infrastructure"}, self.enabled(["lab/aws/scripts/load.py", "tests/scorecard/aws-thresholds.json"]))
        self.assertEqual({"infrastructure", "dotnet"}, self.enabled(["lab/aws/packs/windows-lab/pack.yaml"]))

    def test_independent_languages_stay_independent(self):
        self.assertEqual({"rust"}, self.enabled(["rust/crates/bower-policy/src/lib.rs"]))
        self.assertEqual({"infrastructure"}, self.enabled(["deploy/aws/main.yaml"]))
        self.assertEqual({"powershell"}, self.enabled(["powershell/build.ps1"]))

    def test_azure_templates_keep_contract_checks(self):
        self.assertEqual({"dotnet", "infrastructure"}, self.enabled(["deploy/bicep/main.bicep"]))

    def test_unknown_and_workflow_inputs_fail_safe(self):
        for path in ("global.json", "Directory.Build.props", "new-tool/config.json",
                     ".github/workflows/ci.yml", "tools/ci/select_jobs.py"):
            self.assertEqual(set(JOBS), self.enabled([path]))

    def test_full_runs_every_job_even_without_changes(self):
        self.assertEqual(set(JOBS), self.enabled([], full=True))
        self.assertEqual(set(JOBS), self.enabled(["README.md"], full=True))

    def test_multiple_subsystems_are_unioned(self):
        self.assertEqual({"rust", "ui", "e2e"}, self.enabled(["rust/Cargo.lock", "ui/package.json"]))

    def test_git_diff_handles_renames_deletions_and_multicommit_push(self):
        with tempfile.TemporaryDirectory() as directory:
            def git(*args):
                return subprocess.check_output(["git", "-C", directory, *args], text=True).strip()

            git("init", "--quiet")
            git("config", "user.email", "ci@example.invalid")
            git("config", "user.name", "CI test")
            old = Path(directory, "old\nname.cs")
            old.write_text("old", encoding="utf-8")
            git("add", ".")
            git("commit", "-qm", "base")
            base = git("rev-parse", "HEAD")
            old.rename(Path(directory, "new.cs"))
            git("add", ".")
            git("commit", "-qm", "rename")
            Path(directory, "extra.cs").write_text("extra", encoding="utf-8")
            git("add", ".")
            git("commit", "-qm", "extra")
            # changed_paths runs in the current checkout; use cwd just for this test.
            previous = os.getcwd()
            try:
                os.chdir(directory)
                self.assertEqual({"old\nname.cs", "new.cs", "extra.cs"}, set(changed_paths(base, "HEAD")))
                self.assertEqual(set(changed_paths(base, "HEAD")), set(changed_paths(base, "HEAD", True)))
                head = git("rev-parse", "HEAD")
                git("checkout", "-qb", "target", base)
                Path(directory, "base-only.cs").write_text("base", encoding="utf-8")
                git("add", ".")
                git("commit", "-qm", "target moved")
                git("checkout", "--detach", "--quiet", head)
                self.assertNotIn("base-only.cs", changed_paths("target", "HEAD", True))
                self.assertIn("base-only.cs", changed_paths("target", "HEAD"))
                with self.assertRaises(subprocess.CalledProcessError):
                    changed_paths("missing-ref", "HEAD")
            finally:
                os.chdir(previous)


class MergeGateTests(unittest.TestCase):
    """Execute the workflow's actual gate with synthetic GitHub job outcomes."""

    def gate(self, outcomes=None, selected=None):
        workflow = Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml"
        script = workflow.read_text(encoding="utf-8").split("python3 - <<'PYTHON'\n", 1)[1]
        script = textwrap.dedent(script.split("          PYTHON", 1)[0])
        jobs = ("changes", "workflow-lint", "build-test", "rust", "infrastructure",
                "powershell", "ui", "e2e", "windows-event-log", "docker", "docker-arm64",
                "publish", "package-linux", "package-windows", "install-linux", "install-windows")
        results = {job: {"result": "success"} for job in jobs}
        results["changes"]["outputs"] = {flag: "false" for flag in JOBS}
        results["changes"]["outputs"].update(selected or {})
        for job, outcome in (outcomes or {}).items():
            results[job]["result"] = outcome
        return subprocess.run(
            [sys.executable, "-c", script], env={**os.environ, "RESULTS": json.dumps(results)},
            capture_output=True, text=True,
        ).returncode

    def test_success_and_intentionally_skipped_jobs_pass(self):
        self.assertEqual(0, self.gate())
        self.assertEqual(0, self.gate({"publish": "skipped"}))

    def test_failed_or_cancelled_checks_block(self):
        for state in ("failure", "cancelled"):
            self.assertNotEqual(0, self.gate({"e2e": state}))

    def test_selection_and_lint_must_run(self):
        for job in ("changes", "workflow-lint"):
            self.assertNotEqual(0, self.gate({job: "skipped"}))

    def test_selected_checks_cannot_be_silently_skipped(self):
        self.assertNotEqual(0, self.gate({"install-windows": "skipped"}, {"packaging": "true"}))
        self.assertNotEqual(0, self.gate({"docker-arm64": "skipped"}, {"containers": "true"}))
        self.assertNotEqual(0, self.gate(selected={"rust": ""}))


if __name__ == "__main__":
    unittest.main()
