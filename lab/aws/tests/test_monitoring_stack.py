import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("monitoring_stack", Path(__file__).resolve().parents[1] / "monitoring/stack.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MonitoringStackTests(unittest.TestCase):
    def setUp(self):
        self.template = module.template()
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


if __name__ == "__main__":
    unittest.main()
