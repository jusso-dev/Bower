import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1] / "monitoring"


def helpers(name):
    source = (ROOT / name).read_text().split("python3 - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    tree = ast.parse(source)
    # Load definitions and literal constants only; never execute provisioning in a test.
    allowed = (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef)
    selected = [node for node in tree.body if isinstance(node, allowed) or
                (isinstance(node, ast.Assign) and all(isinstance(target, ast.Name) and target.id.isupper() for target in node.targets))]
    namespace = {}
    exec(compile(ast.Module(body=selected, type_ignores=[]), name, "exec"), namespace)
    return namespace


class FirewallSetupTests(unittest.TestCase):
    def setUp(self):
        self.collector = helpers("setup-firewall-collector.sh")
        self.sender = helpers("setup-firewall-sender.sh")

    def destination(self):
        return {"BOWER_OUTPUT": "azure-logs-ingestion", "BOWER_AZURE_CREDENTIAL": "environment",
                "BOWER_DCE_ENDPOINT": "https://synthetic.ingest.monitor.azure.com",
                "BOWER_DCR_ID": "dcr-" + "a" * 32, "AZURE_TENANT_ID": "11111111-1111-1111-1111-111111111111",
                "AZURE_CLIENT_ID": "22222222-2222-2222-2222-222222222222",
                "AZURE_CLIENT_CERTIFICATE_PATH": "/etc/bower/secrets/ingest.pem"}

    def text(self, values):
        return "".join(key + "=" + value + "\n" for key, value in values.items())

    def test_destination_requires_certificate_based_sentinel_and_preserves_values(self):
        result = self.collector["destination_environment"](self.text(self.destination()))
        self.assertEqual({**self.destination(), "BOWER_STREAM_NAME": "Custom-BowerSecurity"}, result)
        for key, value in (("BOWER_OUTPUT", "ama-spool"), ("BOWER_AZURE_CREDENTIAL", "azure-cli"),
                           ("BOWER_DCE_ENDPOINT", "http://insecure.example"),
                           ("BOWER_DCE_ENDPOINT", "https://user:synthetic-secret@example.invalid"),
                           ("AZURE_CLIENT_CERTIFICATE_PATH", "/tmp/other.pem"), ("AZURE_CLIENT_SECRET", "synthetic-secret")):
            changed = {**self.destination(), key: value}
            with self.subTest(key=key, value=value), self.assertRaises(self.collector["SetupError"]):
                self.collector["destination_environment"](self.text(changed))

    def test_environment_rejects_duplicates_and_unterminated_quotes(self):
        for text in ("BOWER_OUTPUT=azure-logs-ingestion\nBOWER_OUTPUT=ama-spool\n", 'BOWER_OUTPUT="unterminated\n'):
            with self.assertRaises(self.collector["SetupError"]):
                self.collector["parse_environment"](text)

    def test_archive_rejects_links_traversal_and_duplicate_members(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "collector.tar.gz"
            for unsafe in ("../escape", "/collector/absolute", "collector/../escape", "symlink", "duplicate", "collector/./Bower.Collector"):
                with tarfile.open(path, "w:gz") as archive:
                    app = tarfile.TarInfo("collector/Bower.Collector")
                    app.size = 3
                    archive.addfile(app, io.BytesIO(b"app"))
                    bad = tarfile.TarInfo("collector/link" if unsafe == "symlink" else
                                           "collector/Bower.Collector" if unsafe == "duplicate" else unsafe)
                    if unsafe == "symlink":
                        bad.type = tarfile.SYMTYPE
                        bad.linkname = "/etc/passwd"
                    archive.addfile(bad)
                with self.subTest(unsafe=unsafe), self.assertRaises(self.collector["SetupError"]):
                    self.collector["validate_archive"](path)

    def test_regular_publish_archive_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "collector.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                app = tarfile.TarInfo("collector/Bower.Collector")
                app.size = 3
                archive.addfile(app, io.BytesIO(b"app"))
            self.collector["validate_archive"](path)

    def test_existing_helper_generates_the_required_persistent_single_tls_action(self):
        source = ROOT.parent / "scripts/syslog-host.py"
        spec = importlib.util.spec_from_file_location("setup_profile_fixture", source)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc/rsyslog.d").mkdir(parents=True)
            (root / "etc/rsyslog.conf").write_text('global(workDirectory="/var/lib/rsyslog")\nmodule(load="imjournal" StateFile="imjournal.state")\n')

            def local_path(value):
                return root / str(value).lstrip("/")

            with patch.object(tool, "Path", side_effect=local_path), patch.object(tool, "install_cert"), \
                    patch.object(tool, "RESULTS", root / "results"), \
                    patch.object(tool, "sh", return_value="active"), \
                    patch.object(tool.subprocess, "run", return_value=SimpleNamespace(returncode=0)), \
                    contextlib.redirect_stdout(io.StringIO()):
                tool.configure_rsyslog(SimpleNamespace(a="10.0.1.10", b="10.0.1.10", cert="sender-r",
                                                       profile="recommended", rebind=0, only="a13", queue="recommended"))
            configuration = (root / "etc/rsyslog.d/10-bower-lab.conf").read_text()
            self.assertEqual(1, configuration.count('type="omfwd"'))
            for setting in ('port="6514"', 'StreamDriverAuthMode="x509/name"',
                            'StreamDriverPermittedPeers="collector-a.bower.lab"', 'RebindInterval="0"',
                            'ResendLastMSGOnReconnect="on"', 'KeepAlive="on"',
                            'queue.size="200000"', 'queue.maxDiskSpace="2g"',
                            'queue.timeoutEnqueue="86400000"', 'queue.saveOnShutdown="on"',
                            'queue.syncQueueFiles="off"', 'queue.checkpointInterval="100"'):
                self.assertIn(setting, configuration)
            self.assertIn('Ratelimit.Burst="200000"', (root / "etc/rsyslog.conf").read_text())

    def test_relp_transport_generates_one_mutual_tls_omrelp_action_with_the_same_queue(self):
        source = ROOT.parent / "scripts/syslog-host.py"
        spec = importlib.util.spec_from_file_location("setup_relp_profile_fixture", source)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc/rsyslog.d").mkdir(parents=True)
            (root / "etc/rsyslog.conf").write_text('global(workDirectory="/var/lib/rsyslog")\nmodule(load="imjournal" StateFile="imjournal.state")\n')

            def local_path(value):
                return root / str(value).lstrip("/")

            with patch.object(tool, "Path", side_effect=local_path), patch.object(tool, "install_cert"), \
                    patch.object(tool, "RESULTS", root / "results"), \
                    patch.object(tool, "sh", return_value="active"), \
                    patch.object(tool.subprocess, "run", return_value=SimpleNamespace(returncode=0)), \
                    contextlib.redirect_stdout(io.StringIO()):
                tool.configure_rsyslog(SimpleNamespace(a="10.0.1.10", b="10.0.1.10", cert="sender-r", transport="relp",
                                                       profile="recommended", rebind=0, only="a13", queue="recommended"))
            configuration = (root / "etc/rsyslog.d/10-bower-lab.conf").read_text()
            self.assertEqual(1, configuration.count('type="omrelp"'))
            self.assertNotIn('type="omfwd"', configuration)
            for setting in ('module(load="omrelp" tls.tlslib="openssl")', 'port="6514"', 'tls="on"',
                            'tls.authmode="name"', 'tls.permittedpeer=["collector-a.bower.lab"]',
                            'tls.mycert="/etc/pki/bower-lab/sender-r.pem"', 'windowSize="128"', 'timeout="90"',
                            'rebindInterval="0"', 'template="RSYSLOG_SyslogProtocol23Format"',
                            'queue.size="200000"', 'queue.timeoutEnqueue="86400000"', 'queue.saveOnShutdown="on"'):
                self.assertIn(setting, configuration)
        # The omrelp build is pinned to exact upstream sources and the installed rsyslog version.
        self.assertEqual({"librelp", "rsyslog"}, set(tool.RELP_SOURCES))
        for url, digest in tool.RELP_SOURCES.values():
            self.assertTrue(url.startswith("https://"))
            self.assertRegex(digest, "^[0-9a-f]{64}$")
        self.assertIn("rsyslog-8.2204.0.tar.gz", tool.RELP_SOURCES["rsyslog"][0])

    def test_collector_protocol_and_queue_cap_are_validated(self):
        text = (ROOT / "setup-firewall-collector.sh").read_text()
        self.assertIn('if protocol not in ("tls", "relp"):', text)
        self.assertIn('"id": "a13", "protocol": protocol', text)
        self.assertIn("16777216 <= int(queue_cap) <= 1073741824", text)
        sender = (ROOT / "setup-firewall-sender.sh").read_text()
        self.assertIn('if transport not in ("omfwd", "relp"):', sender)

    def test_certificate_fetch_adapter_cannot_request_other_keys_or_destinations(self):
        for key, destination in (("exchange/private-key.pem", "/etc/pki/bower-lab/private-key.pem"),
                                 ("exchange/ca.pem", "/etc/other/ca.pem")):
            with self.assertRaises(self.sender["SetupError"]):
                self.sender["local_certificate_fetch"](Path("/not-read"), key, destination)

    def test_artifacts_are_digest_and_size_checked_before_use(self):
        run = "bower-ws6-20990101-000000"
        for namespace in (self.collector, self.sender):
            for problem in (None, "manifest-digest", "file-digest", "size", "extra-name"):
                with self.subTest(problem=problem), tempfile.TemporaryDirectory() as directory:
                    payload = b"synthetic-artifact"
                    files = {"fixture": {"sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}}
                    if problem == "file-digest":
                        files["fixture"]["sha256"] = "0" * 64
                    if problem == "size":
                        files["fixture"]["bytes"] += 1
                    if problem == "extra-name":
                        files["../outside"] = files["fixture"]
                    manifest = json.dumps({"schemaVersion": 1, "runId": run, "role": "collector", "files": files}).encode()
                    expected_hash = "0" * 64 if problem == "manifest-digest" else hashlib.sha256(manifest).hexdigest()
                    objects = {"manifest.json": manifest, "fixture": payload}
                    requests = []

                    def aws(*args):
                        if args[1] == "sts":
                            return "959038055523"
                        if args[1] == "s3api":
                            key = args[args.index("--key") + 1]
                            requests.append(key)
                            return str(len(objects[key.rsplit("/", 1)[-1]]))
                        key = args[-2].split("s3://synthetic-bucket/", 1)[1]
                        requests.append(key)
                        Path(args[-1]).write_bytes(objects[key.rsplit("/", 1)[-1]])
                        return ""

                    environment = {"BOWER_LAB_RUN": run, "BOWER_LAB_BUCKET": "synthetic-bucket",
                                   "AWS_DEFAULT_REGION": "ap-southeast-2",
                                   "BOWER_ARTIFACT_MANIFEST_SHA256": expected_hash, "BOWER_SETUP_STAGE": directory}
                    with patch.dict(os.environ, environment), patch.object(os, "geteuid", return_value=0), patch.dict(namespace, {"command": aws}):
                        if problem:
                            with self.assertRaises(namespace["SetupError"]):
                                namespace["fetch_artifacts"]("collector", {"fixture": 1024})
                        else:
                            stage, actual_run, actual_hash = namespace["fetch_artifacts"]("collector", {"fixture": 1024})
                            self.assertEqual((Path(directory), run, expected_hash), (stage, actual_run, actual_hash))
                    self.assertTrue(all(key.startswith("artifacts/qualification/" + run + "/collector/") for key in requests))
                    self.assertTrue(all(".." not in key for key in requests))
                    if problem in ("manifest-digest", "extra-name"):
                        self.assertEqual(2, len(requests))

    def test_exception_output_does_not_include_credential_or_command_text(self):
        for namespace in (self.collector, self.sender):
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                namespace["safe_exception"](ValueError, ValueError("synthetic-secret"), None)
            self.assertEqual("firewall-setup: ValueError\n", output.getvalue())


if __name__ == "__main__":
    unittest.main()
