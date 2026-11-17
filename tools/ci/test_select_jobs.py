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
            "website/src/css/custom.css", "website/docusaurus.config.ts", "plans/001-expected-inventory.md",
            "reports/s3-output-bower-s3-20261105-004926/summary.json", "DESIGN.md", "CONTRIBUTING.md",
            ".gitignore", "AGENTS.md", ".github/dependabot.yml",
        ]))

    def test_documentation_runs_the_doc_contract_unit_tests(self):
        # ComplianceCitationTests, CliHelpTests and the Sentinel table test read these.
        for path in ("docs/security/ism-alignment.md", "docs/reference/cli.md",
                     "docs/reference/sentinel-table.md", "docs/security/verified/asvs-5.0.0-logging.json",
                     "tools/docs/generate_cli_reference.py", "tools/compliance/verify_sources.py",
                     "README.md", "PRODUCT.md", "SECURITY.md"):
            with self.subTest(path=path):
                self.assertEqual({"dotnet"}, self.enabled([path]))

    def test_cloudwatch_agent_guide_runs_its_windows_steps(self):
        self.assertEqual({"infrastructure", "dotnet"}, self.enabled(["docs/getting-started/aws-cloudwatch-agent.md"]))

    def test_separate_workflows_do_not_run_ci_jobs(self):
        # workflow-lint (always required) still lints them.
        for path in (".github/workflows/docs.yml", ".github/workflows/images.yml",
                     ".github/workflows/asvs-examples.yml"):
            with self.subTest(path=path):
                self.assertEqual(set(), self.enabled([path]))

    def test_examples_run_their_unit_and_quick_start_checks(self):
        for path in ("examples/asvs-logging/contract/expected.jsonl", "examples/cloud-agents/aws/test_logrotate.sh",
                     "examples/aspnetcore-minimal-api/Program.cs", "examples/policies/collector-health/x.yaml"):
            with self.subTest(path=path):
                self.assertEqual({"dotnet", "infrastructure"}, self.enabled([path]))

    def test_unit_test_content_runs_dotnet_without_platforms(self):
        for path in ("rules/sigma/auth_failure_burst.yml", "tools/queue-migration-check/Program.cs"):
            with self.subTest(path=path):
                self.assertEqual({"dotnet", "windows", "e2e"}, self.enabled([path]))

    def test_package_bumps_outside_the_native_binaries_skip_the_platform_matrix(self):
        # e.g. Dependabot test-tool, SQS and Hangfire bumps (#269, #272).
        result = self.enabled(["Directory.Packages.props", "tests/Bower.UnitTests/packages.lock.json",
                               "src/Bower.Agent.Cloud/packages.lock.json"])
        self.assertEqual(set(JOBS) - {"platforms", "packaging"}, result)

    def test_package_bumps_in_the_native_binaries_build_every_platform(self):
        for lock in ("src/Bower.Cli/packages.lock.json", "src/Bower.Collector/packages.lock.json"):
            with self.subTest(lock=lock):
                self.assertEqual(set(JOBS), self.enabled(["Directory.Packages.props", lock]))
                self.assertTrue({"platforms", "packaging"} <= self.enabled([lock]))

    def test_ui_runs_browser_tests_without_platform_matrix(self):
        self.assertEqual({"ui", "e2e"}, self.enabled(["ui/Bower.Management.Web/src/App.tsx"]))

    def test_source_security_changes_keep_tests_and_windows_coverage(self):
        self.assertEqual({"dotnet", "windows", "e2e", "infrastructure"}, self.enabled([
            "src/Bower.Redaction/Redactor.cs", "tests/Bower.UnitTests/QueueTests.cs",
        ]))

    def test_wec_probe_references_run_lab_infrastructure(self):
        for project in ("Bower.Persistence", "Bower.Source.WindowsEventLog", "Bower.Redaction",
                        "Bower.Abstractions", "Bower.Contracts"):
            with self.subTest(project=project):
                self.assertEqual({"dotnet", "windows", "e2e", "infrastructure"},
                                 self.enabled([f"src/{project}/Changed.cs"]))

    def test_wec_receiving_position_inputs_run_windows_and_lab_checks(self):
        for path in ("lab/aws/tests/test_wec_receiving_position.ps1", "lab/aws/soak/wec-agent.ps1",
                     "lab/aws/wecfix/wec-agent.ps1", "lab/aws/upgrade-recovery/probe/Program.cs",
                     "lab/aws/upgrade-recovery/probe/Bower.LabProbe.csproj",
                     "lab/aws/upgrade-recovery/probe/packages.lock.json"):
            with self.subTest(path=path):
                self.assertEqual({"windows", "infrastructure"}, self.enabled([path]))

    def test_unrelated_lab_inputs_do_not_run_windows_checks(self):
        for path in ("lab/aws/wecfix/reconcile.py", "lab/aws/soak/dc-agent.ps1",
                     "lab/aws/tests/test_wec_receiving_position_extra.ps1",
                     "lab/aws/upgrade-recovery/probes/other.cs"):
            with self.subTest(path=path):
                self.assertEqual({"infrastructure"}, self.enabled([path]))

    def test_unrelated_sources_do_not_run_lab_infrastructure(self):
        for path in ("src/Bower.Source.Syslog/SyslogSource.cs", "src/Bower.Collector/Program.cs",
                     "src/Bower.PersistenceExtra/Other.cs", "tests/Bower.UnitTests/QueueTests.cs"):
            with self.subTest(path=path):
                self.assertEqual({"dotnet", "windows", "e2e"}, self.enabled([path]))

    def test_shared_assets_test_the_collector_and_tooling(self):
        result = self.enabled(["packs/windows-security-logon/parsers/security-4625.json"])
        self.assertTrue({"dotnet", "powershell", "e2e"} <= result)

    def test_default_policy_changes_validate_installers(self):
        self.assertTrue({"platforms", "packaging"} <= self.enabled(["policies/default/policy.json"]))

    def test_installer_changes_have_all_artifacts_and_install_checks(self):
        for path in ("deploy/installers/windows/build.ps1", "deploy/systemd/bower.service",
                     "tests/installers/linux.sh", "deploy/ansible/roles/bower/tasks/main.yml"):
            with self.subTest(path=path):
                self.assertTrue({"dotnet", "platforms", "packaging", "powershell"} <= self.enabled([path]))

    def test_syslog_output_changes_run_the_installer_syslog_test(self):
        # tests/installers/ama-syslog-output-linux.sh runs it under the packaged unit (#245).
        self.assertTrue({"dotnet", "platforms", "packaging"} <= self.enabled(["src/Bower.Output.AmaSyslog/AmaSyslogOutput.cs"]))

    def test_relay_and_enrolment_keep_container_integration(self):
        for path in ("src/Bower.Collector/Relay/Listener.cs", "src/Bower.Forwarding/Client.cs",
                     "tests/e2e/enrolment.sh", "tests/e2e/aws-emulator.sh",
                     "tests/e2e/aws-emulator/Dockerfile"):
            with self.subTest(path=path):
                self.assertIn("containers", self.enabled([path]))

    def test_aws_emulator_inputs_run_container_integration(self):
        for path in ("deploy/aws/bower-aws-security.yaml", "deploy/aws/bower-s3-output.yaml",
                     "packs/aws-security/policies/aws-findings.yaml",
                     "tests/fixtures/aws-emulator/guardduty-finding.json",
                     "src/Bower.Agent.Cloud/Aws/SqsMessageSource.cs",
                     "src/Bower.Source.Aws/AwsQueueMessageParser.cs", "src/Bower.Output.S3/S3Output.cs"):
            with self.subTest(path=path):
                self.assertIn("containers", self.enabled([path]))
        self.assertNotIn("containers", self.enabled(["deploy/gcp/main.tf"]))
        self.assertNotIn("containers", self.enabled(["packs/gcp-security/pack.yaml"]))

    def test_docker_changes_test_cross_architecture_builds(self):
        for path in ("deploy/docker/Dockerfile", ".dockerignore", "docker-compose.yml"):
            self.assertIn("containers", self.enabled([path]))

    def test_aws_lab_checks_do_not_build_platforms(self):
        self.assertEqual({"infrastructure"}, self.enabled(["lab/aws/scripts/load.py", "tests/scorecard/aws-thresholds.json"]))
        self.assertEqual({"infrastructure", "dotnet"}, self.enabled(["lab/aws/packs/windows-lab/pack.yaml"]))

    def test_independent_languages_stay_independent(self):
        self.assertEqual({"infrastructure"}, self.enabled(["deploy/aws/main.yaml"]))
        self.assertEqual({"powershell"}, self.enabled(["powershell/build.ps1"]))

    def test_azure_templates_keep_contract_checks(self):
        self.assertEqual({"dotnet", "infrastructure"}, self.enabled(["deploy/bicep/main.bicep"]))
        self.assertEqual({"dotnet", "infrastructure"}, self.enabled(["deploy/sentinel/analytics/rules/firewall-deny.kql"]))

    def test_unknown_and_workflow_inputs_fail_safe(self):
        for path in ("global.json", "Directory.Build.props", "Directory.Solution.targets",
                     "nuget.config", "Bower.sln", "new-tool/config.json",
                     ".github/workflows/ci.yml", "tools/ci/select_jobs.py"):
            self.assertEqual(set(JOBS), self.enabled([path]))

    def test_full_runs_every_job_even_without_changes(self):
        self.assertEqual(set(JOBS), self.enabled([], full=True))
        self.assertEqual(set(JOBS), self.enabled(["website/package.json"], full=True))

    def test_multiple_subsystems_are_unioned(self):
        self.assertEqual({"powershell", "ui", "e2e"}, self.enabled(["powershell/build.ps1", "ui/package.json"]))

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
        jobs = ("changes", "version", "workflow-lint", "build-test", "linux-arm64", "infrastructure",
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
            # The version job feeds every artefact; it is always required.
            self.assertNotEqual(0, self.gate({"version": state}))

    def test_selection_and_lint_must_run(self):
        for job in ("changes", "workflow-lint"):
            self.assertNotEqual(0, self.gate({job: "skipped"}))

    def test_selected_checks_cannot_be_silently_skipped(self):
        self.assertNotEqual(0, self.gate({"install-windows": "skipped"}, {"packaging": "true"}))
        self.assertNotEqual(0, self.gate({"docker-arm64": "skipped"}, {"containers": "true"}))
        self.assertNotEqual(0, self.gate({"linux-arm64": "skipped"}, {"dotnet": "true"}))
        self.assertNotEqual(0, self.gate(selected={"dotnet": ""}))


if __name__ == "__main__":
    unittest.main()
