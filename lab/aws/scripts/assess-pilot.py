#!/usr/bin/env python3
"""Assess metadata-only native pilot reports; an upload acknowledgement is not proof."""
import argparse
import datetime as dt
import json
import re
from pathlib import Path


PHASES = [
    ('steady', 10, 600), ('burst', 100, 60), ('outage-burst', 100, 60),
    ('outage-steady', 10, 3540), ('drain-with-live-traffic', 10, 600),
]
EXPECTED = sum(rate * seconds for _, rate, seconds in PHASES)
LINUX_CHECKS = ['completed', 'generatedAtTargetRate', 'nativePacketCount', 'noSourceLoss',
                'outageAtLeastOneHour', 'backlogRetained', 'backlogDrainedWithinTenMinutes',
                'noDeadLetters', 'allAcceptedAcknowledged', 'sqliteIntegrity', 'samplingSucceeded']
WINDOWS_CHECKS = ['completed', 'outageAtLeastOneHour', 'backlogRetained',
                  'backlogDrainedWithinTenMinutes', 'noDeadLetters', 'noPendingAtEnd']


def phase_checks(phases, windows=False):
    if len(phases) != len(PHASES):
        return False
    for phase, (name, rate, seconds) in zip(phases, PHASES):
        count = phase.get('completed' if windows else 'sent')
        if (phase.get('name') != name or count != rate * seconds
                or phase.get('targetRate' if windows else 'rate') != rate
                or phase.get('seconds', 0) < seconds
                or not rate * .99 <= phase.get('actualRate', 0) <= rate * 1.01):
            return False
        if windows and (not phase.get('allCallsCompleted')
                        or phase.get('attempted') != count
                        or phase.get('unexpectedSuccessfulLogons') != 0
                        or phase.get('ldapResultCodes') != {'49': count}):
            return False
    return True


def destination_matches(group, count, digest):
    return (count > 0 and isinstance(digest, str) and len(digest) == 64
            and group.get('distinctIds') == count and group.get('rows') == count
            and group.get('identitySetSha256') == digest
            and group.get('duplicateRows') == 0 and group.get('rawPrivacyMatches') == 0)


def distinct_destination_matches(group, count, digest):
    """Supplemental at-least-once proof; never overrides the strict verdict."""
    rows = group.get('rows')
    duplicates = group.get('duplicateRows')
    return (count > 0 and isinstance(digest, str) and len(digest) == 64
            and group.get('distinctIds') == count
            and group.get('identitySetSha256') == digest
            and isinstance(rows, int) and isinstance(duplicates, int)
            and rows >= count and duplicates == rows - count
            and group.get('rawPrivacyMatches') == 0)


def same_window(*values):
    try:
        times = [dt.datetime.fromisoformat(re.sub(r'\.(\d+)(?=[Z+-])',
                 lambda match: '.' + (match.group(1) + '000000')[:6], value).replace('Z', '+00:00'))
                 for value in values]
        return all(value.tzinfo is not None for value in times) and len(set(times)) == 1
    except (TypeError, ValueError, AttributeError):
        return False


def host_checks(report, required, drain_seconds):
    return (all(report.get('checks', {}).get(key) is True for key in required)
            and report.get('passed') is True and report.get('failureType') is None
            and report.get('outageSeconds', 0) >= 3600
            and report.get('backlogAtRestore', 0) >= 41400
            and isinstance(drain_seconds, (int, float)) and 0 <= drain_seconds <= 600)


def policy_hashes_match(expected, *observed):
    """Compare every observed policy set with an independently pinned signed profile."""
    def valid(values):
        return (isinstance(values, list) and bool(values)
                and all(isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value)
                        for value in values)
                and len(set(values)) == len(values))
    return (valid(expected) and bool(observed)
            and all(valid(values) and set(values) == set(expected) for values in observed))


def assess(linux, generator, monitor, source, wec, destination, policies):
    """Require the whole declared envelope and independent destination identities."""
    linux_total = linux.get('finalAccepted', 0)
    windows_group = destination.get('windowsCampaign', {})
    linux_group = destination.get('groups', {}).get('network_connection_denied', {})
    checks = {
        'linuxPhases': phase_checks(linux.get('phases', [])),
        'linuxNativePopulation': linux.get('generated') == EXPECTED == linux.get('nativePackets')
            and linux_total - linux.get('initialAccepted', 0) == EXPECTED,
        'linuxHostChecks': host_checks(linux, LINUX_CHECKS,
            (linux.get('drain') or {}).get('secondsAfterRestore'))
            and linux.get('finalDelivered') == linux_total,
        'linuxDestination': destination_matches(linux_group, linux_total, linux.get('identitySetSha256')),
        'linuxPolicyProvenance': policy_hashes_match(policies.get('linux'),
            linux_group.get('policyHashes'), destination.get('linuxCampaign', {}).get('policyHashes')),
        'linuxCampaignWindow': same_window(destination.get('linuxSince'), linux.get('startedAt'))
            and destination.get('linuxCampaign', {}).get('rows') == EXPECTED
            and destination.get('linuxCampaign', {}).get('distinctIds') == EXPECTED
            and destination.get('linuxCampaign', {}).get('rawPrivacyMatches') == 0,
        'windowsPhases': phase_checks(generator.get('phases', []), windows=True),
        'windowsHostChecks': host_checks(monitor, WINDOWS_CHECKS, monitor.get('drainSeconds')),
        'windowsNativePopulation': source.get('selectedNativeRecords') == EXPECTED
            and wec.get('selectedNativeRecords') == EXPECTED
            and source.get('distinctNativeIds') == EXPECTED
            and wec.get('distinctNativeIds') == EXPECTED,
        'windowsSourceToWec': source.get('rawNativeIdentitySetSha256') is not None
            and source.get('rawNativeIdentitySetSha256') == wec.get('rawNativeIdentitySetSha256')
            and source.get('nativeIdentitySetSha256') == wec.get('nativeIdentitySetSha256')
            and source.get('noIdentityCollisions') is True and wec.get('noIdentityCollisions') is True,
        'windowsQueue': wec.get('nativeAndQueueMatch') is True
            and wec.get('queueRows') == EXPECTED == wec.get('deliveredRows')
            and wec.get('sqliteIntegrity') is True,
        'windowsPrivacy': all(wec.get(key) is True for key in
            ['noRawUsername', 'usernamePseudonymized', 'databaseAndWalExcludeUsername']),
        'windowsDestination': destination_matches(windows_group, EXPECTED, wec.get('queueIdentitySetSha256')),
        'windowsPolicyProvenance': policy_hashes_match(policies.get('windows'),
            wec.get('policyHashes'), windows_group.get('policyHashes')),
        'independentQuery': destination.get('queryStatus') == 200
            and destination.get('queryRole') == 'verifier'
            and destination.get('partialError') is False,
        'sameWindowsWindow': same_window(source.get('since'), wec.get('since'),
            destination.get('windowsSince'), generator.get('startedAt'), monitor.get('startedAt')),
        'sameRun': bool(generator.get('runId'))
            and generator.get('runId') == monitor.get('runId') == linux.get('runId'),
        'resourceMeasurements': all(bool(report.get('samples'))
            and report.get('peakCollectorResidentBytes', 0) > 0
            and report.get('minimumFreeDiskBytes', 0) >= 512 * 1024 * 1024
            and report.get('maximumDbWalBytes', 0) > 0 for report in [linux, monitor]),
    }
    return {'profile': 'wec-firewall-sentinel-pilot-v1', 'expectedEventsPerCollector': EXPECTED,
            'checks': checks, 'passed': all(checks.values()),
            'destinationObservations': {
                'linuxDistinctIdentitiesMatch': distinct_destination_matches(
                    linux_group, linux_total, linux.get('identitySetSha256')),
                'windowsDistinctIdentitiesMatch': distinct_destination_matches(
                    windows_group, EXPECTED, wec.get('queueIdentitySetSha256')),
                'linuxDuplicateRows': linux_group.get('duplicateRows'),
                'windowsDuplicateRows': windows_group.get('duplicateRows'),
                'semantics': 'At-least-once delivery can replay ambiguous acknowledgements. '
                    'These observations do not override the strict zero-duplicate checks.'},
            'scope': 'Measured native pilot envelope only; not a signed production-release approval.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['linux', 'generator', 'monitor', 'source', 'wec', 'destination', 'policies']:
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    report = assess(**{name: json.loads(path.read_text()) for name, path in vars(args).items()})
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
