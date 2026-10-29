import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("lab_template", Path(__file__).resolve().parents[1] / "scripts/template.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TemplateTests(unittest.TestCase):
    def setUp(self):
        self.template = module.template()
        self.resources = self.template["Resources"]

    def of_type(self, name):
        return [r for r in self.resources.values() if r["Type"] == "AWS::" + name]

    def test_seven_hosts_are_private_and_use_imdsv2(self):
        hosts = self.of_type("EC2::Instance")
        self.assertEqual(7, len(hosts))
        for host in hosts:
            p = host["Properties"]
            self.assertEqual({"Ref": "PrivateSubnet"}, p["SubnetId"])
            self.assertNotIn("KeyName", p)
            self.assertNotIn("UserData", p)
            self.assertEqual("required", p["MetadataOptions"]["HttpTokens"])

    def test_windows_starts_small_with_explicit_fallback(self):
        self.assertEqual("t3.micro", self.template["Parameters"]["WindowsType"]["Default"])
        self.assertEqual(["t3.micro", "t3.small"], self.template["Parameters"]["WindowsType"]["AllowedValues"])

    def test_all_disks_encrypted_and_deleted_with_host(self):
        for host in self.of_type("EC2::Instance"):
            for disk in host["Properties"]["BlockDeviceMappings"]:
                self.assertTrue(disk["Ebs"]["Encrypted"])
                self.assertTrue(disk["Ebs"]["DeleteOnTermination"])
        self.assertEqual(2, len(self.resources["Collector"]["Properties"]["BlockDeviceMappings"]))

    def test_no_external_ingress_or_ssh_rdp(self):
        rules = [r["Properties"] for r in self.of_type("EC2::SecurityGroupIngress")]
        for group in self.of_type("EC2::SecurityGroup"):
            rules.extend(group["Properties"].get("SecurityGroupIngress", []))
        for rule in rules:
            self.assertIn("SourceSecurityGroupId", rule)
            self.assertNotIn(rule["FromPort"], [22, 3389])
            self.assertNotIn("CidrIp", rule)

    def test_all_hosts_are_tagged_to_this_run(self):
        for host in self.of_type("EC2::Instance"):
            tags = {t["Key"]: t["Value"] for t in host["Properties"]["Tags"]}
            self.assertEqual("bower-lab", tags["Project"])
            self.assertEqual({"Ref": "RunId"}, tags["RunId"])
            self.assertIn("Expiry", tags)

    def test_bucket_is_private_encrypted_and_expires(self):
        bucket = self.resources["Results"]
        self.assertEqual("Retain", bucket["DeletionPolicy"])
        p = bucket["Properties"]
        self.assertTrue(all(p["PublicAccessBlockConfiguration"].values()))
        self.assertIn("BucketEncryption", p)
        self.assertEqual(90, p["LifecycleConfiguration"]["Rules"][0]["ExpirationInDays"])

    def test_control_commands_are_run_scoped(self):
        policies = self.resources["ControlRole"]["Properties"]["Policies"]
        policy = next(p["PolicyDocument"] for p in policies if p["PolicyName"] == "RunLab")
        instances = next(s for s in policy["Statement"] if s.get("Condition"))
        conditions = instances["Condition"]["StringEquals"]
        self.assertEqual("bower-lab", conditions["ssm:resourceTag/Project"])
        self.assertEqual({"Ref": "RunId"}, conditions["ssm:resourceTag/RunId"])

    def test_expiry_only_mutates_exact_resources(self):
        policy = self.resources["ExpiryWorkerRole"]["Properties"]["Policies"][0]["PolicyDocument"]
        self.assertNotIn("*", policy["Statement"][0]["Resource"])
        state = self.resources["ExpiryWorker"]["Properties"]["Definition"]["States"]
        self.assertEqual(7, len(state["Terminate"]["Parameters"]["InstanceIds"]))
        self.assertEqual(5, len(state["Endpoints"]["Parameters"]["VpcEndpointIds"]))
        self.assertIn("Retry", state["Address"])


if __name__ == "__main__":
    unittest.main()
