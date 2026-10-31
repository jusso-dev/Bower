import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("storage_lab", Path(__file__).resolve().parents[1] / "scripts/storage-lab.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class StorageLabTemplateTests(unittest.TestCase):
    def setUp(self):
        self.template = module.template()
        self.resources = self.template["Resources"]

    def of_type(self, name):
        return {key: r for key, r in self.resources.items() if r["Type"] == "AWS::" + name}

    def test_hosts_are_private_imdsv2_and_terminate_on_shutdown(self):
        hosts = self.of_type("EC2::Instance")
        self.assertEqual({"Linux", "Dc", "Wec"}, set(hosts))
        for host in hosts.values():
            properties = host["Properties"]
            self.assertEqual({"Ref": "Subnet"}, properties["SubnetId"])
            self.assertNotIn("KeyName", properties)
            self.assertNotIn("UserData", properties)
            self.assertNotIn("NetworkInterfaces", properties)
            self.assertEqual("required", properties["MetadataOptions"]["HttpTokens"])
            self.assertEqual("terminate", properties["InstanceInitiatedShutdownBehavior"])
        self.assertFalse(self.resources["Subnet"]["Properties"]["MapPublicIpOnLaunch"])

    def test_disks_are_encrypted_and_queue_volumes_small(self):
        for name, host in self.of_type("EC2::Instance").items():
            disks = host["Properties"]["BlockDeviceMappings"]
            for disk in disks:
                self.assertTrue(disk["Ebs"]["Encrypted"])
                self.assertTrue(disk["Ebs"]["DeleteOnTermination"])
            sizes = [disk["Ebs"]["VolumeSize"] for disk in disks[1:]]
            self.assertEqual({"Linux": [1], "Wec": [2], "Dc": []}[name], sizes)

    def test_no_ingress_from_outside_the_group(self):
        group = self.resources["Hosts"]["Properties"]
        self.assertNotIn("SecurityGroupIngress", group)
        for rule in self.of_type("EC2::SecurityGroupIngress").values():
            self.assertEqual({"Ref": "Hosts"}, rule["Properties"]["SourceSecurityGroupId"])
            self.assertNotIn("CidrIp", rule["Properties"])

    def test_every_taggable_resource_carries_the_run(self):
        for name, resource in self.resources.items():
            tags = resource["Properties"].get("Tags")
            if tags is None:
                continue
            values = {tag["Key"]: tag["Value"] for tag in tags}
            self.assertEqual("bower-lab", values["Project"], name)
            self.assertEqual({"Ref": "RunId"}, values["RunId"], name)

    def test_expiry_guard_terminates_only_these_hosts(self):
        worker = self.resources["ExpiryWorker"]["Properties"]["Definition"]["States"]["Terminate"]
        self.assertEqual([{"Ref": name} for name in ("Linux", "Dc", "Wec")], worker["Parameters"]["InstanceIds"])
        statement = self.resources["ExpiryWorkerRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][0]
        self.assertEqual("ec2:TerminateInstances", statement["Action"])
        self.assertEqual(3, len(statement["Resource"]))

    def test_host_role_reads_only_this_run(self):
        statements = self.resources["HostRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
        for statement in statements:
            self.assertIn("${RunId}", statement["Resource"]["Fn::Sub"])

    def test_run_id_pattern(self):
        self.assertRegex("bower-ws3-20261031-081023", module.RUN_PATTERN)
        self.assertEqual(module.RUN_PATTERN, self.template["Parameters"]["RunId"]["AllowedPattern"])


if __name__ == "__main__":
    unittest.main()
