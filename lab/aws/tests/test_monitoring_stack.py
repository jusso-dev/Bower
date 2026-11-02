import importlib.util
import ast
import contextlib
import io
import json
import os
import re
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("monitoring_stack", Path(__file__).resolve().parents[1] / "monitoring/stack.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
run_spec = importlib.util.spec_from_file_location("monitoring_run", Path(__file__).resolve().parents[1] / "monitoring/run.py")
run_module = importlib.util.module_from_spec(run_spec)
run_spec.loader.exec_module(run_module)


class MonitoringStackTests(unittest.TestCase):
    def test_security_group_rule_descriptions_use_ec2_allowed_characters(self):
        allowed = re.compile(r'^[a-zA-Z0-9. _\-:/()#,@\[\]+=&;{}!$*]{0,255}$')
        for resource in module.template()['Resources'].values():
            properties = resource.get('Properties', {})
            rules = []
            if resource['Type'] in ('AWS::EC2::SecurityGroupIngress', 'AWS::EC2::SecurityGroupEgress'):
                rules.append(properties)
            if resource['Type'] == 'AWS::EC2::SecurityGroup':
                rules.extend(properties.get('SecurityGroupIngress', []))
                rules.extend(properties.get('SecurityGroupEgress', []))
            for rule in rules:
                self.assertRegex(rule.get('Description', ''), allowed)

    @staticmethod
    def configured_template(sender=False, windows=True):
        """Resolve only the optional topology conditions, leaving AWS references symbolic."""
        omitted = object()
        enabled = {"WithSyslogSender": sender, "WithWindows": windows}

        def resolve(value):
            if value == {"Ref": "AWS::NoValue"}:
                return omitted
            if isinstance(value, list):
                return [item for child in value if (item := resolve(child)) is not omitted]
            if isinstance(value, dict):
                if isinstance(value.get("Condition"), str) and not enabled.get(value["Condition"], True):
                    return omitted
                if "Fn::If" in value:
                    condition, yes, no = value["Fn::If"]
                    assert condition in enabled
                    return resolve(yes if enabled[condition] else no)
                return {key: item for key, child in value.items() if (item := resolve(child)) is not omitted}
            return value

        return resolve(module.template())

    def setUp(self):
        self.template = self.configured_template()
        self.resources = self.template["Resources"]

    def of_type(self, name):
        return [r for r in self.resources.values() if r["Type"] == "AWS::" + name]

    def test_hosts_are_private_imdsv2_encrypted_and_self_terminating(self):
        hosts = self.of_type("EC2::Instance")
        self.assertEqual(2, len(hosts))
        self.assertFalse(self.resources["PrivateSubnet"]["Properties"]["MapPublicIpOnLaunch"])
        for host in hosts:
            p = host["Properties"]
            self.assertEqual({"Ref": "PrivateSubnet"}, p["SubnetId"])
            self.assertNotIn("KeyName", p)
            self.assertNotIn("UserData", p)
            self.assertEqual("required", p["MetadataOptions"]["HttpTokens"])
            self.assertEqual("terminate", p["InstanceInitiatedShutdownBehavior"])
            for disk in p["BlockDeviceMappings"]:
                self.assertTrue(disk["Ebs"]["Encrypted"])
                self.assertTrue(disk["Ebs"]["DeleteOnTermination"])

    def test_no_inbound_rules(self):
        self.assertEqual([], self.resources["HostGroup"]["Properties"]["SecurityGroupIngress"])
        self.assertEqual([], self.of_type("EC2::SecurityGroupIngress"))
        for rule in self.resources["HostGroup"]["Properties"]["SecurityGroupEgress"]:
            self.assertIn(rule["FromPort"], (80, 443))

    def test_everything_taggable_is_tagged_to_this_run(self):
        for name, resource in self.resources.items():
            tags = resource["Properties"].get("Tags")
            if tags is None:
                continue
            values = {t["Key"]: t["Value"] for t in tags}
            self.assertEqual("bower-lab", values["Project"], name)
            self.assertEqual({"Ref": "RunId"}, values["RunId"], name)

    def test_bucket_is_private_encrypted_and_expires(self):
        p = self.resources["Artifacts"]["Properties"]
        self.assertTrue(all(p["PublicAccessBlockConfiguration"].values()))
        self.assertIn("BucketEncryption", p)
        self.assertEqual(2, p["LifecycleConfiguration"]["Rules"][0]["ExpirationInDays"])

    def test_host_role_reads_only_artifacts_and_writes_only_results(self):
        statements = self.resources["HostRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
        resources = {s["Action"]: s["Resource"] for s in statements}
        self.assertEqual({"Fn::Sub": "${Artifacts.Arn}/artifacts/*"}, resources["s3:GetObject"])
        self.assertEqual({"Fn::Sub": "${Artifacts.Arn}/results/*"}, resources["s3:PutObject"])

    def test_expiry_terminates_exactly_the_two_hosts(self):
        statement = self.resources["ExpiryRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][0]
        self.assertEqual("ec2:TerminateInstances", statement["Action"])
        self.assertEqual(2, len(statement["Resource"]))
        self.assertNotIn("*", str(statement["Resource"]))
        target = self.resources["ExpirySchedule"]["Properties"]["Target"]
        self.assertEqual("arn:aws:scheduler:::aws-sdk:ec2:terminateInstances", target["Arn"])

    def test_firewall_only_topology_has_no_windows_host_or_expiry_target(self):
        template = self.configured_template(sender=True, windows=False)
        resources = template["Resources"]
        self.assertNotIn("Windows", resources)
        self.assertEqual({"Linux", "Sender"}, {name for name, item in resources.items() if item["Type"] == "AWS::EC2::Instance"})
        self.assertNotIn("WindowsId", template["Outputs"])
        statement = resources["ExpiryRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][0]
        self.assertEqual(2, len(statement["Resource"]))
        self.assertNotIn("Windows", json.dumps(statement["Resource"]))
        target = resources["ExpirySchedule"]["Properties"]["Target"]["Input"]
        self.assertEqual({"Fn::Sub": ['{"InstanceIds":["${L}","${S}"]}', {"L": {"Ref": "Linux"}, "S": {"Ref": "Sender"}}]}, target)
        self.assertEqual("true", module.template()["Parameters"]["EnableWindows"]["Default"])
        self.assertRegex("bower-fw-20261101-120000", module.template()["Parameters"]["RunId"]["AllowedPattern"])

    def test_sender_is_opt_in_and_disabled_topology_has_no_sender_references(self):
        raw = module.template()
        self.assertEqual("false", raw["Parameters"]["EnableSyslogSender"]["Default"])
        self.assertEqual({"Fn::Equals": [{"Ref": "EnableSyslogSender"}, "true"]},
                         raw["Conditions"]["WithSyslogSender"])
        self.assertNotIn('"Ref": "Sender"', json.dumps(self.template["Resources"]))
        self.assertNotIn("SenderId", self.template["Outputs"])
        self.assertNotIn("SenderIp", self.template["Outputs"])
        self.assertEqual([{"Ref": "HostGroup"}], self.resources["Linux"]["Properties"]["SecurityGroupIds"])

    def test_optional_sender_has_scoped_tls_network_and_expiry(self):
        configured = self.configured_template(sender=True)
        resources = configured["Resources"]
        instances = {name: resource["Properties"] for name, resource in resources.items()
                     if resource["Type"] == "AWS::EC2::Instance"}
        self.assertEqual({"Linux", "Windows", "Sender"}, set(instances))
        self.assertEqual([{"Ref": "HostGroup"}], instances["Windows"]["SecurityGroupIds"])
        self.assertEqual([{"Ref": "HostGroup"}, {"Ref": "CollectorSyslogGroup"}], instances["Linux"]["SecurityGroupIds"])
        self.assertEqual([{"Ref": "HostGroup"}, {"Ref": "SenderGroup"}], instances["Sender"]["SecurityGroupIds"])
        self.assertEqual({"Ref": "SenderProfile"}, instances["Sender"]["IamInstanceProfile"])
        sender_access = resources["SenderRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
        self.assertEqual({"s3:GetObject": {"Fn::Sub": "${Artifacts.Arn}/artifacts/qualification/${RunId}/sender/*"},
                          "s3:PutObject": {"Fn::Sub": "${Artifacts.Arn}/results/sender/*"}},
                         {statement["Action"]: statement["Resource"] for statement in sender_access})
        ingress = [r["Properties"] for r in resources.values() if r["Type"] == "AWS::EC2::SecurityGroupIngress"]
        self.assertEqual(1, len(ingress))
        rule = ingress[0]
        self.assertEqual({"Ref": "CollectorSyslogGroup"}, rule["GroupId"])
        self.assertEqual({"Ref": "SenderGroup"}, rule["SourceSecurityGroupId"])
        self.assertEqual(("tcp", 6514, 6514), (rule["IpProtocol"], rule["FromPort"], rule["ToPort"]))
        self.assertNotIn("CidrIp", rule)
        self.assertNotIn("CidrIpv6", rule)
        for name, instance in instances.items():
            self.assertNotIn("KeyName", instance, name)
            self.assertEqual({"Ref": "PrivateSubnet"}, instance["SubnetId"], name)
            self.assertEqual("required", instance["MetadataOptions"]["HttpTokens"], name)
            self.assertEqual("terminate", instance["InstanceInitiatedShutdownBehavior"], name)
            for disk in instance["BlockDeviceMappings"]:
                self.assertTrue(disk["Ebs"]["Encrypted"], name)
                self.assertTrue(disk["Ebs"]["DeleteOnTermination"], name)
        statement = resources["ExpiryRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][0]
        self.assertEqual(3, len(statement["Resource"]))
        self.assertNotIn("*", str(statement["Resource"]))
        for name in instances:
            self.assertIn({"Fn::Sub": "arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/${" + name + "}"},
                          statement["Resource"])
        schedule_input = resources["ExpirySchedule"]["Properties"]["Target"]["Input"]["Fn::Sub"]
        self.assertEqual('{"InstanceIds":["${L}","${W}","${S}"]}', schedule_input[0])
        self.assertEqual({"Ref": "Sender"}, schedule_input[1]["S"])

    def test_extra_environment_cannot_inject_commands_or_override_owned_run(self):
        self.assertEqual({"example": "a=b"}, run_module.extra_environment(["example=a=b"]))
        for items in [["X;touch /tmp/no=value"], ["BOWER_LAB_RUN=other"],
                      ["aws_default_region=other"], ["x=one", "X=two"], ["NO_EQUALS"]]:
            with self.subTest(items=items), self.assertRaises(ValueError):
                run_module.extra_environment(items)

    def test_sender_command_rejects_wrong_role_before_sending_ssm(self):
        state = {"runId": "bower-ws6-20990101-000000", "outputs": {"SenderId": "i-owned"}}
        instance = {"State": {"Name": "running"}, "Tags": [
            {"Key": "Project", "Value": "bower-lab"}, {"Key": "RunId", "Value": state["runId"]},
            {"Key": "Role", "Value": "linux-collector"}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps(state), encoding="utf-8")
            with patch.object(run_module, "aws", side_effect=[{"Account": run_module.ACCOUNT},
                    {"Reservations": [{"Instances": [instance]}]}]) as aws:
                with self.assertRaisesRegex(SystemExit, "role does not match"):
                    run_module.main(["Sender", "unused.sh", "--state", str(path)])
                self.assertEqual(2, aws.call_count)

    def test_sender_command_rejects_disabled_sender_before_ec2_or_ssm(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps({"runId": "bower-ws6-20990101-000000", "outputs": {}}), encoding="utf-8")
            with patch.object(run_module, "aws", return_value={"Account": run_module.ACCOUNT}) as aws:
                with self.assertRaisesRegex(SystemExit, "not enabled"):
                    run_module.main(["Sender", "unused.sh", "--state", str(path)])
                self.assertEqual(1, aws.call_count)


class UploadOwnershipTests(unittest.TestCase):
    def test_only_expected_account_and_run_tag_allow_upload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            aws = root / "aws"
            aws.write_text("""#!/bin/bash
printf '%s\n' "$*" >> "$AWS_TEST_LOG"
case " $* " in
  *" sts get-caller-identity "*) printf '%s\n' "$AWS_TEST_ACCOUNT" ;;
  *" s3api get-bucket-tagging "*) printf '%s\n' "$AWS_TEST_TAGS" ;;
  *" s3 sync "*) exit 0 ;;
  *) exit 1 ;;
esac
""")
            aws.chmod(0o755)
            state = root / "state.json"
            state.write_text(json.dumps({"runId": "bower-ws6-20261031-074751", "outputs": {"Bucket": "test-bucket"}}))
            script = Path(__file__).resolve().parents[1] / "monitoring/upload.sh"
            for account, project, run_tag, should_upload in (("959038055523", "bower-lab", "bower-ws6-20261031-074751", True),
                                                             ("000000000000", "bower-lab", "bower-ws6-20261031-074751", False),
                                                             ("959038055523", "bower-lab", "other-run", False),
                                                             ("959038055523", "other-project", "bower-ws6-20261031-074751", False)):
                log = root / "calls"
                log.write_text("")
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                           AWS_TEST_LOG=str(log), AWS_TEST_ACCOUNT=account, PYTHONOPTIMIZE="1",
                           AWS_TEST_TAGS=json.dumps({"TagSet": [{"Key": "Project", "Value": project},
                                                               {"Key": "RunId", "Value": run_tag}]}))
                result = subprocess.run(["bash", str(script), str(state), str(root)], env=env,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(should_upload, result.returncode == 0)
                self.assertEqual(should_upload, " s3 sync " in " " + log.read_text())


class DrillCredentialTests(unittest.TestCase):
    def test_drill_scripts_do_not_put_bearer_tokens_in_arguments(self):
        scripts = Path(__file__).resolve().parents[1] / "monitoring"
        for path in scripts.glob("*.sh"):
            contents = path.read_text()
            with self.subTest(script=path.name):
                self.assertNotIn('-H "Authorization: Bearer $token"', contents)
                self.assertNotIn('python3 - "$token"', contents)

    def test_replay_drill_does_not_follow_authenticated_redirects(self):
        script = (Path(__file__).resolve().parents[1] / "monitoring/drill-replay.sh").read_text()
        python = script.split("python3 - <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        self.assertIn("urllib.request.build_opener(NoRedirect())", python)
        self.assertIn("opener.open(request, timeout=10)", python)
        self.assertNotIn("urllib.request.urlopen(request", python)
        tree = ast.parse(python)
        handler_node = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "NoRedirect")
        namespace = {"urllib": urllib}
        exec(compile(ast.Module(body=[handler_node], type_ignores=[]), "drill-replay.sh", "exec"), namespace)
        handler = namespace["NoRedirect"]()

        class Sink(BaseHTTPRequestHandler):
            requests = 0
            def do_POST(self):
                type(self).requests += 1
                self.send_response(200)
                self.end_headers()
            def log_message(self, *args):
                pass
        target = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
        threading.Thread(target=target.serve_forever, daemon=True).start()

        class Redirect(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{target.server_port}/stolen")
                self.end_headers()
            def log_message(self, *args):
                pass
        source = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        threading.Thread(target=source.serve_forever, daemon=True).start()
        try:
            request = urllib.request.Request(f"http://127.0.0.1:{source.server_port}/events",
                                             data=b"{}", headers={"Authorization": "Bearer synthetic-marker"})
            with self.assertRaises(urllib.error.HTTPError):
                urllib.request.build_opener(handler).open(request, timeout=5)
            self.assertEqual(0, Sink.requests)
            self.assertIsNone(handler.redirect_request(request, None, 302, "Found", {}, "http://other.example/"))
            # Execute the actual embedded drill with a synthetic token and local
            # redirect endpoint. A redirect must not be reported as a posted event.
            class TestInputs(ast.NodeTransformer):
                def visit_Assign(self, node):
                    if any(isinstance(target, ast.Name) and target.id == "token" for target in node.targets):
                        node.value = ast.Constant(value="synthetic-marker")
                    return self.generic_visit(node)
                def visit_Constant(self, node):
                    if node.value == "http://127.0.0.1:4319/v1/events":
                        return ast.copy_location(ast.Constant(value=f"http://127.0.0.1:{source.server_port}/events"), node)
                    return node
            output = io.StringIO()
            with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as stopped:
                exec(compile(ast.fix_missing_locations(TestInputs().visit(tree)), "drill-replay.sh", "exec"), {})
            self.assertIn("HTTP 302", str(stopped.exception))
            self.assertNotIn("synthetic-marker", output.getvalue())
            self.assertNotIn("posted", output.getvalue())
            self.assertEqual(0, Sink.requests)
        finally:
            source.shutdown()
            source.server_close()
            target.shutdown()
            target.server_close()


class MonitoringCoverageQueryTests(unittest.TestCase):
    def test_unqualified_dcr_rule_requires_separate_opt_in(self):
        template = (Path(__file__).resolve().parents[3] / "deploy/sentinel/monitoring/monitoring.bicep").read_text()
        self.assertIn("param enableUnqualifiedDcrErrorQuery bool = false", template)
        self.assertIn("param enableUnqualifiedTableNoIngestionQuery bool = false", template)
        self.assertIn("param enableDcrErrorLogs bool = false", template)
        self.assertIn("enabled: enabled && (rule.name != 'dcr-errors' || enableUnqualifiedDcrErrorQuery) && (rule.name != 'table-no-ingestion' || enableUnqualifiedTableNoIngestionQuery)", template)

    def test_truncated_or_unknown_coverage_alerts(self):
        queries = Path(__file__).resolve().parents[3] / "deploy/sentinel/monitoring/queries"
        transport = (queries / "source-transport-errors.kql").read_text()
        expiry = (queries / "syslog-tls-expiry.kql").read_text()
        for flag in ("syslogComplete", "windowsEventLogComplete"):
            self.assertIn(f"coalesce(tobool(Attributes.monitoringCoverage.{flag}), false) == false", transport)
        self.assertIn('Source = "syslog:coverage-incomplete"', transport)
        self.assertIn('Source = "winevt:coverage-incomplete"', transport)
        self.assertIn("or CoverageIncomplete", transport)
        self.assertIn("make_set_if(TimeGenerated, Retrying, 2)", transport)
        self.assertIn('make_set_if(TimeGenerated, State == "backpressure" or RetryCount > 0, 2)', transport)
        self.assertIn("ImpairedRecords >= 2", transport)
        self.assertIn("coalesce(tobool(Attributes.monitoringCoverage.syslogComplete), false) == false", expiry)
        self.assertIn('Source = "syslog:coverage-incomplete"', expiry)
        self.assertIn('Protocol !in ("tls", "tcp", "udp", "relp")', expiry)
        self.assertIn('Tls = Protocol == "tls" or (Protocol == "relp"', expiry)
        # Unconfigured optional client CA / revocation list files are not unknown metadata;
        # records without the flags (older collectors) still are.
        self.assertIn("coalesce(tobool(Listener.clientCertificateAuthorityConfigured), true)", expiry)
        self.assertIn("coalesce(tobool(Listener.clientRevocationListConfigured), true)", expiry)
        self.assertIn("(RevocationListConfigured and isnull(RevocationListNextUpdate))", expiry)
        self.assertIn('coalesce(tobool(Listener.tls), isnotnull(ServerCertificateNotAfter))', expiry)
        self.assertIn("| where Tls\n", expiry)
        self.assertIn("coalesce(toint(Listener.relpBusyCloses), 0) > 0", transport)
        self.assertIn("isnull(RevocationListNextUpdate)", expiry)
        self.assertIn("TlsMetadataIncomplete = true", expiry)
        self.assertIn("union expiry, listenerUnknown, incomplete", expiry)

    def test_queue_queries_report_missing_metrics_as_unknown(self):
        queries = Path(__file__).resolve().parents[3] / "deploy/sentinel/monitoring/queries"
        storage = (queries / "queue-storage.kql").read_text()
        backlog = (queries / "queue-backlog.kql").read_text()
        self.assertIn("isnull(QueuePagesUsedPercent) or isnull(CapacityUsedPercent)", storage)
        self.assertIn("not(isfinite(QueuePagesUsedPercent))", storage)
        self.assertIn("StorageSignal = StorageMetricsIncomplete or", storage)
        self.assertNotIn("coalesce(QueuePagesUsedPercent, 0.0)", storage)
        self.assertIn("isnull(Undelivered) or Undelivered < 0", backlog)
        self.assertIn("Undelivered > 0 and (isnull(OldestUndeliveredAgeSeconds)", backlog)
        self.assertIn("where BacklogMetricsIncomplete or", backlog)


if __name__ == "__main__":
    unittest.main()
