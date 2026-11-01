#!/usr/bin/env python3
"""Build the isolated, single-Linux-host security qualification template.

The existing VPC and NAT are inputs only. Expiry terminates the instance; it
does not remove the stack, bucket or other billable resources. Always perform
and independently verify teardown after the test.
"""

import argparse
import importlib.util
import json
from pathlib import Path


def template():
    source = Path(__file__).with_name('stack.py')
    spec = importlib.util.spec_from_file_location('monitoring_stack', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.template()
    resources = result['Resources']
    for name in ('Windows', 'Sender', 'SenderRole', 'SenderProfile',
                 'CollectorSyslogGroup', 'SenderGroup', 'SenderToCollectorSyslog'):
        del resources[name]
    resources['Linux']['Properties']['SecurityGroupIds'] = [{'Ref': 'HostGroup'}]
    resources['Linux']['Metadata'] = module.context(
        'Private, SSM-only Linux host for isolated security tests.',
        'Do not add public addresses or inbound rules.')
    statement = resources['ExpiryRole']['Properties']['Policies'][0]['PolicyDocument']['Statement'][0]
    statement['Resource'] = [{'Fn::Sub': 'arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/${Linux}'}]
    resources['ExpiryRole']['Metadata'] = module.context(
        'Expiry may terminate only this security test instance.',
        'Never use a wildcard instance resource.')
    resources['ExpirySchedule']['Properties']['Target']['Input'] = {
        'Fn::Sub': ['{"InstanceIds":["${L}"]}', {'L': {'Ref': 'Linux'}}]
    }
    resources['ExpirySchedule']['Metadata'] = module.context(
        'Independent expiry terminates only the security test instance.',
        'Teardown must still empty the bucket and remove the stack.')
    result.pop('Conditions')
    for name in ('EnableSyslogSender', 'WindowsImage'):
        del result['Parameters'][name]
    for name in ('WindowsId', 'WindowsIp', 'SenderId', 'SenderIp'):
        del result['Outputs'][name]
    result['Description'] = 'Bower security qualification: one private Linux host, SSM only, self-expiring'
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(template(), indent=1), encoding='utf-8')
