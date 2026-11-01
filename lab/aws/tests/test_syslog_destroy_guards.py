import importlib.util
import contextlib
import io
import json
from pathlib import Path
import unittest
import tempfile
import subprocess
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("syslog_lab", Path(__file__).resolve().parents[1] / "scripts/syslog-lab.py")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class DestroyOwnershipTests(unittest.TestCase):
    def test_rejects_unowned_resources_before_any_mutation(self):
        run = "bower-ws1-20261031-075451"
        bucket = run + "-artifacts"
        state = {"runId": run, "stack": run, "outputs": {"Bucket": bucket}}
        correct_tags = [{"Key": "Project", "Value": "bower-lab"}, {"Key": "RunId", "Value": run}]
        cases = ("account", "stack_tags", "bucket_output", "bucket_tags", "bucket_tag_error", "valid")
        for case in cases:
            with self.subTest(case=case):
                calls = []

                def aws(*args, **_kwargs):
                    calls.append(args)
                    if args[:2] == ("sts", "get-caller-identity"):
                        return {"Account": "000000000000" if case == "account" else lab.ACCOUNT}
                    if args[:2] == ("cloudformation", "describe-stacks"):
                        return {"Stacks": [{"StackStatus": "CREATE_COMPLETE", "Tags": [] if case == "stack_tags" else correct_tags,
                                            "Outputs": [{"OutputKey": "Bucket", "OutputValue": "wrong-bucket" if case == "bucket_output" else bucket}]}]}
                    if args[:2] == ("s3api", "get-bucket-tagging"):
                        if case == "bucket_tag_error":
                            raise RuntimeError("tag lookup failed")
                        return {"TagSet": [] if case == "bucket_tags" else correct_tags}
                    if args[:2] == ("s3api", "list-object-versions"):
                        return {"Versions": [{"Key": "owned", "VersionId": "v1"}], "DeleteMarkers": []}
                    if args[:2] in (("s3api", "delete-object"), ("cloudformation", "delete-stack")):
                        return {}
                    raise AssertionError(f"unexpected AWS call: {args}")

                with patch.object(lab, "aws", side_effect=aws), patch.object(lab.subprocess, "run") as runner, \
                     patch.object(lab, "capture_volume_inventory") as capture, patch.object(lab, "save_state") as save:
                    if case == "valid":
                        with contextlib.redirect_stdout(io.StringIO()):
                            lab.destroy_run(state, Path("unused-state"))
                        capture.assert_called_once()
                        save.assert_called_once()
                        self.assertEqual(2, runner.call_count)
                        self.assertIn(("cloudformation", "delete-stack", "--stack-name", run), calls)
                        self.assertIn(("s3api", "delete-object", "--bucket", bucket, "--key", "owned", "--version-id", "v1"), calls)
                    else:
                        with self.assertRaises((ValueError, RuntimeError)):
                            lab.destroy_run(state, Path("unused-state"))
                        runner.assert_not_called()
                        capture.assert_not_called()
                        save.assert_not_called()
                        self.assertFalse(any(call[:2] in (("s3api", "delete-object"), ("cloudformation", "delete-stack")) for call in calls))


class SendOwnershipTests(unittest.TestCase):
    def test_public_environment_rejects_reserved_names_duplicates_and_invalid_values(self):
        self.assertEqual({"RATE": "10"}, lab.parse_environment(["RATE=10"]))
        for items in (["BOWER_LAB_RUN=other"], ["bower_lab_bucket=other"], ["AWS_DEFAULT_REGION=x"],
                      ["BOWER_LAB_HOST=x"], ["RATE=1", "RATE=2"], ["RATE=1", "rate=2"],
                      ["RATE=$(cmd)"], ["NO_EQUALS"]):
            with self.subTest(items=items), self.assertRaises(ValueError):
                lab.parse_environment(items)

    def test_send_rejects_unbounded_execution_timeout_before_aws(self):
        for timeout in (0, 7201, True):
            with self.subTest(timeout=timeout), patch.object(lab, "aws") as aws:
                with self.assertRaises(ValueError):
                    lab.send({}, "SenderR", Path("unused"), {}, timeout)
                aws.assert_not_called()

    def test_send_checks_account_stack_bucket_and_host_before_ssm(self):
        run = "bower-ws1-20261031-075451"
        bucket = run + "-artifacts"
        tags = [{"Key": "Project", "Value": "bower-lab"}, {"Key": "RunId", "Value": run}]
        with tempfile.TemporaryDirectory() as directory:
            state = {"runId": run, "stack": run, "directory": directory,
                     "outputs": {"Bucket": bucket, "SenderRId": "i-123"}}
            script = Path(directory) / "script.sh"
            script.write_text("#!/bin/bash\ntrue\n")
            for case in ("account", "stack", "bucket", "host_output", "host_tags", "valid"):
                with self.subTest(case=case):
                    calls = []
                    def aws(*args, **_kwargs):
                        calls.append(args)
                        if args[:2] == ("sts", "get-caller-identity"):
                            return {"Account": "0" if case == "account" else lab.ACCOUNT}
                        if args[:2] == ("cloudformation", "describe-stacks"):
                            return {"Stacks": [{"StackStatus": "CREATE_COMPLETE", "Tags": [] if case == "stack" else tags,
                                                "Outputs": [{"OutputKey": "Bucket", "OutputValue": bucket},
                                                            {"OutputKey": "SenderRId", "OutputValue": "i-other" if case == "host_output" else "i-123"}]}]}
                        if args[:2] == ("s3api", "get-bucket-tagging"):
                            return {"TagSet": [] if case == "bucket" else tags}
                        if args[:2] == ("ec2", "describe-instances"):
                            return {"Reservations": [{"Instances": [{"Tags": [] if case == "host_tags" else tags,
                                                                     "State": {"Name": "running"}}]}]}
                        if args[:2] == ("ssm", "send-command"):
                            return {"Command": {"CommandId": "test-command"}}
                        raise AssertionError(f"unexpected AWS call: {args}")
                    with patch.object(lab, "aws", side_effect=aws):
                        if case == "valid":
                            result = lab.send(state, "SenderR", script, {"RATE": "10"}, 60)
                            self.assertEqual("test-command", result["commandId"])
                            self.assertEqual(60, result["executionTimeoutSeconds"])
                        else:
                            with self.assertRaises(ValueError):
                                lab.send(state, "SenderR", script, {"RATE": "10"}, 60)
                            self.assertFalse(any(call[:2] == ("ssm", "send-command") for call in calls))


class InvocationWaitTests(unittest.TestCase):
    def test_retries_only_invocation_not_found_and_pending_until_success(self):
        record = {"commandId": "c", "instanceId": "i", "executionTimeoutSeconds": 30}
        absent = lab.AwsCliError(invocation_not_found=True)
        with patch.object(lab, "aws", side_effect=[absent, {"Status": "Pending"}, {"Status": "Success"}]) as aws, \
             patch.object(lab.time, "sleep"):
            self.assertEqual("Success", lab.wait(record)["Status"])
            self.assertEqual(3, aws.call_count)
            self.assertTrue(all(0 < call.kwargs["timeout"] <= 30 for call in aws.call_args_list))

    def test_persistent_auth_failure_is_immediate_and_does_not_echo_error(self):
        error = lab.AwsCliError()
        with patch.object(lab, "aws", side_effect=error) as aws, patch.object(lab.time, "sleep") as sleep:
            with self.assertRaises(RuntimeError) as raised:
                lab.wait({"commandId": "c", "instanceId": "i", "executionTimeoutSeconds": 30})
            self.assertNotIn("synthetic-secret-marker", str(raised.exception))
            self.assertEqual(1, aws.call_count)
            sleep.assert_not_called()

    def test_pending_not_found_and_cli_timeout_respect_deadline(self):
        record = {"commandId": "c", "instanceId": "i", "executionTimeoutSeconds": 1}
        for result in ({"Status": "InProgress"},
                       lab.AwsCliError(invocation_not_found=True),
                       TimeoutError("AWS CLI request timed out")):
            with self.subTest(result=type(result).__name__):
                now = [0.0]
                def sleep(seconds):
                    now[0] += seconds
                with patch.object(lab, "aws", side_effect=result if isinstance(result, Exception) else None,
                                  return_value=result) as aws, \
                     patch.object(lab.time, "monotonic", side_effect=lambda: now[0]), \
                     patch.object(lab.time, "sleep", side_effect=sleep):
                    with self.assertRaises(TimeoutError):
                        lab.wait(record, poll=1000)
                    self.assertEqual(661, now[0])
                    self.assertEqual(1, aws.call_count)

    def test_invalid_timeout_and_status_fail_closed(self):
        for timeout in (None, 0, 7201, True):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                lab.wait({"commandId": "c", "instanceId": "i", "executionTimeoutSeconds": timeout})
        with patch.object(lab, "aws", return_value={"Status": "unexpected"}):
            with self.assertRaises(RuntimeError):
                lab.wait({"commandId": "c", "instanceId": "i", "executionTimeoutSeconds": 30})


class AwsTimeoutTests(unittest.TestCase):
    def test_cli_calls_use_finite_timeouts_and_never_echo_errors(self):
        for invalid in (None, 0, float("inf"), True):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                lab.aws("sts", "get-caller-identity", timeout=invalid)
        with patch.object(lab.subprocess, "run") as runner:
            runner.return_value.stdout = "{}"
            self.assertEqual({}, lab.aws("sts", "get-caller-identity"))
            self.assertEqual(120, runner.call_args.kwargs["timeout"])
            lab.aws_wait_or_remove("cloudformation", "wait", "stack-delete-complete")
            self.assertEqual(1800, runner.call_args.kwargs["timeout"])
        failures = (subprocess.TimeoutExpired("synthetic-secret-marker", 120),
                    subprocess.CalledProcessError(1, "synthetic-secret-marker", stderr="secret-marker"))
        for failure in failures:
            with self.subTest(failure=type(failure).__name__), patch.object(lab.subprocess, "run", side_effect=failure):
                with self.assertRaises((TimeoutError, lab.AwsCliError)) as raised:
                    lab.aws("sts", "get-caller-identity")
                self.assertNotIn("secret-marker", str(raised.exception))
        with patch.object(lab.subprocess, "run") as runner:
            runner.return_value.stdout = "synthetic-secret-marker"
            with self.assertRaises(RuntimeError) as raised:
                lab.aws("sts", "get-caller-identity")
            self.assertNotIn("synthetic-secret-marker", str(raised.exception))

    def test_cli_classifies_invocation_not_found_without_echoing_details(self):
        error = subprocess.CalledProcessError(1, "aws", stderr="An error occurred (InvocationDoesNotExist) when calling the GetCommandInvocation operation: secret-marker")
        with patch.object(lab.subprocess, "run", side_effect=error):
            with self.assertRaises(lab.AwsCliError) as raised:
                lab.aws("ssm", "get-command-invocation")
        self.assertTrue(raised.exception.invocation_not_found)
        self.assertNotIn("secret-marker", str(raised.exception))


class AuditEvidenceTests(unittest.TestCase):
    def test_missing_or_duplicate_instance_ids_fail_closed(self):
        run = "bower-ws1-20261031-075451"
        ids = {name + "Id": f"i-{index:08x}" for index, name in enumerate(lab.HOSTS, 1)}
        for variant in ("complete", "missing", "duplicate", "missing_subnet", "invalid_subnet"):
            outputs = dict(ids, SubnetId="subnet-00000001")
            if variant == "missing":
                outputs.pop("SenderRId")
            elif variant == "duplicate":
                outputs["SenderRId"] = outputs["SenderGId"]
            elif variant == "missing_subnet":
                outputs.pop("SubnetId")
            elif variant == "invalid_subnet":
                outputs["SubnetId"] = "not-a-subnet"
            state = {"runId": run, "stack": run, "outputs": outputs,
                     "volumeInventory": {value: [f"vol-{index:08x}"] for index, value in enumerate(ids.values(), 1)},
                     "resources": [{"type": "AWS::StepFunctions::StateMachine", "physicalId": "sm"},
                                   {"type": "AWS::Scheduler::Schedule", "physicalId": "sched"}],
                     "parameters": {"NatGatewayId": "nat-123"}}
            def aws(*args, **_kwargs):
                key = args[:2]
                if key == ("cloudformation", "list-stacks"): return {"StackSummaries": []}
                if key == ("ec2", "describe-instances"):
                    return {"Reservations": [{"Instances": [{"InstanceId": value, "State": {"Name": "terminated"}} for value in ids.values()]}]}
                if key == ("ec2", "describe-volumes") and "--volume-ids" in args:
                    raise lab.AwsCliError(volume_not_found=True)
                keys = {("ec2", "describe-volumes"): "Volumes", ("ec2", "describe-snapshots"): "Snapshots",
                        ("ec2", "describe-security-groups"): "SecurityGroups", ("ec2", "describe-subnets"): "Subnets",
                        ("ec2", "describe-route-tables"): "RouteTables", ("ec2", "describe-network-interfaces"): "NetworkInterfaces",
                        ("iam", "list-roles"): "Roles", ("iam", "list-instance-profiles"): "InstanceProfiles",
                        ("s3api", "list-buckets"): "Buckets", ("stepfunctions", "list-state-machines"): "stateMachines",
                        ("scheduler", "list-schedules"): "Schedules", ("logs", "describe-log-groups"): "logGroups",
                        ("secretsmanager", "list-secrets"): "SecretList"}
                if key == ("ec2", "describe-nat-gateways"): return {"NatGateways": [{"State": "available"}]}
                if key in keys: return {keys[key]: []}
                raise AssertionError(f"unexpected AWS call: {args}")
            with self.subTest(variant=variant), patch.object(lab, "aws", side_effect=aws):
                result = lab.audit(state)
                self.assertEqual(variant == "complete", result["passed"])
                if variant in ("missing", "duplicate"):
                    self.assertFalse(result["checks"]["allRunInstancesObserved"])
                if variant in ("missing_subnet", "invalid_subnet"):
                    self.assertFalse(result["checks"]["noSubnetInterfaces"])


class VolumeInventoryTests(unittest.TestCase):
    def setUp(self):
        self.run = "bower-ws1-20261031-075451"
        self.ids = {host: f"i-{index:08x}" for index, host in enumerate(lab.HOSTS, 1)}
        self.volumes = {instance: f"vol-{index:08x}" for index, instance in enumerate(self.ids.values(), 1)}
        self.tags = [{"Key": "Project", "Value": "bower-lab"}, {"Key": "RunId", "Value": self.run}]
        self.state = {"runId": self.run, "outputs": {host + "Id": instance for host, instance in self.ids.items()}}
        self.stack = {"Outputs": [{"OutputKey": host + "Id", "OutputValue": instance} for host, instance in self.ids.items()]}

    def test_capture_uses_exact_owned_instances_and_preserves_earlier_volumes(self):
        first = self.ids["CollectorA"]
        previous = {instance: [volume] for instance, volume in self.volumes.items()}
        previous[first].append("vol-000000ff")
        self.state["volumeInventory"] = previous
        calls = []
        def aws(*args, **_kwargs):
            calls.append(args)
            instance = args[-1]
            return {"Reservations": [{"Instances": [{"InstanceId": instance, "Tags": self.tags,
                    "State": {"Name": "running"}, "RootDeviceName": "/dev/root",
                    "BlockDeviceMappings": [{"DeviceName": "/dev/root", "Ebs": {"VolumeId": self.volumes[instance]}}]}]}]}
        with patch.object(lab, "aws", side_effect=aws):
            lab.capture_volume_inventory(self.state, self.stack)
        self.assertEqual(set(self.ids.values()), set(self.state["volumeInventory"]))
        self.assertIn("vol-000000ff", self.state["volumeInventory"][first])
        self.assertEqual({("ec2", "describe-instances", "--instance-ids", item) for item in self.ids.values()}, set(calls))

    def test_terminated_instance_requires_prior_complete_inventory(self):
        def terminated(*args, **_kwargs):
            return {"Reservations": [{"Instances": [{"InstanceId": args[-1], "Tags": self.tags,
                    "State": {"Name": "terminated"}, "BlockDeviceMappings": []}]}]}
        with patch.object(lab, "aws", side_effect=terminated), self.assertRaises(ValueError):
            lab.capture_volume_inventory(self.state, self.stack)
        previous = {instance: [volume] for instance, volume in self.volumes.items()}
        self.state["volumeInventory"] = previous
        with patch.object(lab, "aws", side_effect=terminated):
            lab.capture_volume_inventory(self.state, self.stack)
        self.assertEqual(previous, self.state["volumeInventory"])

    def test_capture_rejects_wrong_tag_missing_root_and_stack_mismatch(self):
        for variant in ("wrong_tag", "missing_root", "stack_mismatch", "duplicate_volume"):
            with self.subTest(variant=variant):
                stack = dict(self.stack)
                if variant == "stack_mismatch":
                    stack["Outputs"] = [{"OutputKey": host + "Id", "OutputValue": "i-ffffffff" if host == "CollectorA" else instance}
                                        for host, instance in self.ids.items()]
                def aws(*args, **_kwargs):
                    instance = args[-1]
                    mapping = {"DeviceName": "/dev/other" if variant == "missing_root" else "/dev/root",
                               "Ebs": {"VolumeId": "vol-00000001" if variant == "duplicate_volume" else self.volumes[instance]}}
                    return {"Reservations": [{"Instances": [{"InstanceId": instance,
                            "Tags": [] if variant == "wrong_tag" else self.tags, "State": {"Name": "running"},
                            "RootDeviceName": "/dev/root", "BlockDeviceMappings": [mapping]}]}]}
                with patch.object(lab, "aws", side_effect=aws), self.assertRaises(ValueError):
                    lab.capture_volume_inventory(self.state, stack)
                self.assertNotIn("volumeInventory", self.state)

    def test_recorded_absence_queries_each_exact_id_and_fails_closed(self):
        self.state["volumeInventory"] = {instance: [volume] for instance, volume in self.volumes.items()}
        queries = []
        def absent(*args, **_kwargs):
            queries.append(args[-1])
            raise lab.AwsCliError(volume_not_found=True)
        with patch.object(lab, "aws", side_effect=absent):
            self.assertTrue(lab.recorded_volumes_absent(self.state))
        self.assertEqual(set(self.volumes.values()), set(queries))
        with patch.object(lab, "aws", return_value={"Volumes": [{"VolumeId": next(iter(self.volumes.values()))}]}):
            self.assertFalse(lab.recorded_volumes_absent(self.state))
        with patch.object(lab, "aws", return_value={"Volumes": []}):
            self.assertFalse(lab.recorded_volumes_absent(self.state))
        with patch.object(lab, "aws", side_effect=lab.AwsCliError()):
            with self.assertRaises(lab.AwsCliError):
                lab.recorded_volumes_absent(self.state)
        self.state["volumeInventory"].pop(next(iter(self.volumes)))
        with patch.object(lab, "aws") as aws:
            self.assertFalse(lab.recorded_volumes_absent(self.state))
            aws.assert_not_called()

    def test_destroy_persists_complete_inventory_before_any_mutation(self):
        bucket = self.run + "-artifacts"
        self.state.update({"stack": self.run})
        self.state["outputs"]["Bucket"] = bucket
        self.stack.update({"StackStatus": "CREATE_COMPLETE", "Tags": self.tags})
        self.stack["Outputs"].append({"OutputKey": "Bucket", "OutputValue": bucket})
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            mutation_calls = []
            def aws(*args, **_kwargs):
                if args[:2] == ("sts", "get-caller-identity"): return {"Account": lab.ACCOUNT}
                if args[:2] == ("cloudformation", "describe-stacks"): return {"Stacks": [self.stack]}
                if args[:2] == ("s3api", "get-bucket-tagging"): return {"TagSet": self.tags}
                if args[:2] == ("ec2", "describe-instances"):
                    instance = args[-1]
                    return {"Reservations": [{"Instances": [{"InstanceId": instance, "Tags": self.tags,
                            "State": {"Name": "running"}, "RootDeviceName": "/dev/root",
                            "BlockDeviceMappings": [{"DeviceName": "/dev/root", "Ebs": {"VolumeId": self.volumes[instance]}}]}]}]}
                if args[:2] == ("s3api", "list-object-versions"): return {"Versions": [], "DeleteMarkers": []}
                if args[:2] == ("cloudformation", "delete-stack"):
                    mutation_calls.append(args)
                    return {}
                raise AssertionError(f"unexpected AWS call: {args}")
            def guarded_mutation(*args):
                persisted = json.loads(state_path.read_text())
                self.assertTrue(lab.valid_volume_inventory(persisted))
                self.assertEqual(set(self.volumes.values()), {value for entries in persisted["volumeInventory"].values() for value in entries})
                mutation_calls.append(args)
            with patch.object(lab, "aws", side_effect=aws), patch.object(lab, "aws_wait_or_remove", side_effect=guarded_mutation), \
                 contextlib.redirect_stdout(io.StringIO()):
                lab.destroy_run(self.state, state_path)
            self.assertEqual(3, len(mutation_calls))

    def test_state_write_failure_prevents_deletion(self):
        bucket = self.run + "-artifacts"
        self.state.update({"stack": self.run})
        self.state["outputs"]["Bucket"] = bucket
        with patch.object(lab, "verify_account"), patch.object(lab, "verify_stack", return_value=self.stack), \
             patch.object(lab, "verified_bucket", return_value=bucket), patch.object(lab, "capture_volume_inventory"), \
             patch.object(lab, "save_state", side_effect=OSError("write failed")), \
             patch.object(lab, "aws_wait_or_remove") as mutate:
            with self.assertRaises(OSError):
                lab.destroy_run(self.state, Path("unused"))
            mutate.assert_not_called()

    def test_only_specific_volume_not_found_error_is_classified(self):
        error = subprocess.CalledProcessError(1, "aws", stderr="An error occurred (InvalidVolume.NotFound) when calling the DescribeVolumes operation: synthetic-secret-marker")
        with patch.object(lab.subprocess, "run", side_effect=error):
            with self.assertRaises(lab.AwsCliError) as raised:
                lab.aws("ec2", "describe-volumes", "--volume-ids", "vol-00000001")
        self.assertTrue(raised.exception.volume_not_found)
        self.assertNotIn("synthetic-secret-marker", str(raised.exception))
        ambiguous = subprocess.CalledProcessError(1, "aws", stderr="An error occurred (AccessDenied) when calling DescribeVolumes: (InvalidVolume.NotFound)")
        with patch.object(lab.subprocess, "run", side_effect=ambiguous):
            with self.assertRaises(lab.AwsCliError) as denied:
                lab.aws("ec2", "describe-volumes", "--volume-ids", "vol-00000001")
        self.assertFalse(denied.exception.volume_not_found)


if __name__ == "__main__":
    unittest.main()
