"""Offline topology and expiry checks for the single-host security lab."""

import importlib.util
import json
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / 'monitoring/security_stack.py'
spec = importlib.util.spec_from_file_location('security_stack', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SecurityStackTests(unittest.TestCase):
    def test_isolated_single_host_and_owned_expiry(self):
        stack = module.template()
        resources = stack['Resources']
        hosts = {name: resource for name, resource in resources.items()
                 if resource['Type'] == 'AWS::EC2::Instance'}
        self.assertEqual({'Linux'}, set(hosts))
        host = hosts['Linux']['Properties']
        self.assertEqual('t3.small', host['InstanceType'])
        self.assertEqual([{'Ref': 'HostGroup'}], host['SecurityGroupIds'])
        self.assertEqual('terminate', host['InstanceInitiatedShutdownBehavior'])
        self.assertEqual('required', host['MetadataOptions']['HttpTokens'])
        self.assertFalse(resources['PrivateSubnet']['Properties']['MapPublicIpOnLaunch'])
        self.assertEqual([], resources['HostGroup']['Properties']['SecurityGroupIngress'])
        self.assertNotIn('UserData', host)
        self.assertNotIn('KeyName', host)
        disk = host['BlockDeviceMappings'][0]['Ebs']
        self.assertEqual(20, disk['VolumeSize'])
        self.assertTrue(disk['Encrypted'])
        self.assertTrue(disk['DeleteOnTermination'])
        role = resources['ExpiryRole']['Properties']['Policies'][0]['PolicyDocument']['Statement'][0]
        self.assertEqual('ec2:TerminateInstances', role['Action'])
        self.assertEqual([{'Fn::Sub': 'arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/${Linux}'}], role['Resource'])
        target = resources['ExpirySchedule']['Properties']['Target']['Input']
        self.assertEqual({'Fn::Sub': ['{"InstanceIds":["${L}"]}', {'L': {'Ref': 'Linux'}}]}, target)
        self.assertEqual('UTC', resources['ExpirySchedule']['Properties']['ScheduleExpressionTimezone'])
        serialized = json.dumps(stack)
        for removed in ('WithSyslogSender', 'WindowsImage', 'WindowsId', 'SenderId', 'CollectorSyslogGroup'):
            self.assertNotIn(removed, serialized)
        self.assertNotIn('AWS::EC2::NatGateway', serialized)

        references = set()

        def collect(value):
            if isinstance(value, dict):
                if 'Ref' in value:
                    references.add(value['Ref'])
                if 'Fn::GetAtt' in value:
                    references.add(value['Fn::GetAtt'][0])
                for child in value.values():
                    collect(child)
            elif isinstance(value, list):
                for child in value:
                    collect(child)

        collect(stack)
        unresolved = {ref for ref in references if not ref.startswith('AWS::')}
        unresolved -= set(resources) | set(stack['Parameters'])
        self.assertEqual(set(), unresolved)


if __name__ == '__main__':
    unittest.main()
