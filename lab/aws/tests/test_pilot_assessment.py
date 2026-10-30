"""Prevent partial phases or mismatched independent proof from qualifying a pilot."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('assessment', Path(__file__).parents[1]/'scripts/assess-pilot.py')
assessment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assessment)


class PilotAssessmentTests(unittest.TestCase):
    def reports(self):
        digest = 'a' * 64
        policy_hash = 'sha256:' + 'c' * 64
        since = '2026-10-30T09:28:00+00:00'
        phases = [{'name':name, 'rate':rate, 'targetRate':rate, 'seconds':seconds,
                   'actualRate':rate, 'sent':rate*seconds, 'attempted':rate*seconds,
                   'completed':rate*seconds, 'allCallsCompleted':True,
                   'unexpectedSuccessfulLogons':0, 'ldapResultCodes':{'49':rate*seconds}}
                  for name, rate, seconds in assessment.PHASES]
        metrics = {'samples':[[0]], 'peakCollectorResidentBytes':100000000,
                   'minimumFreeDiskBytes':1000000000, 'maximumDbWalBytes':100000000}
        host = {'checks':{key:True for key in assessment.LINUX_CHECKS + assessment.WINDOWS_CHECKS},
                'passed':True, 'failureType':None, 'outageSeconds':3600, 'backlogAtRestore':41400,
                'drainSeconds':90, 'drain':{'secondsAfterRestore':90}, **metrics}
        native = {'selectedNativeRecords':59400, 'distinctNativeIds':59400,
                  'rawNativeIdentitySetSha256':digest, 'nativeIdentitySetSha256':digest,
                  'noIdentityCollisions':True, 'since':since}
        group = {'rows':59400, 'distinctIds':59400, 'identitySetSha256':digest,
                 'duplicateRows':0, 'rawPrivacyMatches':0, 'policyHashes':[policy_hash]}
        return dict(linux={**host, 'phases':phases, 'generated':59400, 'nativePackets':59400, 'runId':'run', 'startedAt':since,
                           'finalAccepted':59400, 'finalDelivered':59400, 'initialAccepted':0, 'identitySetSha256':digest},
                    generator={'phases':phases, 'runId':'run', 'startedAt':since},
                    monitor={**host, 'runId':'run', 'startedAt':since}, source=native,
                    wec={**native, 'nativeAndQueueMatch':True, 'queueRows':59400, 'policyHashes':[policy_hash],
                         'deliveredRows':59400, 'queueIdentitySetSha256':digest,
                         'sqliteIntegrity':True, 'noRawUsername':True,
                         'usernamePseudonymized':True, 'databaseAndWalExcludeUsername':True},
                    destination={'groups':{'network_connection_denied':group},
                                 'linuxSince':since, 'linuxCampaign':copy.deepcopy(group),
                                 'windowsCampaign':copy.deepcopy(group), 'queryStatus':200, 'queryRole':'verifier',
                                 'partialError':False, 'windowsSince':since},
                    policies={'linux':[policy_hash], 'windows':[policy_hash]})

    def test_complete_reconciled_campaign_passes(self):
        self.assertTrue(assessment.assess(**self.reports())['passed'])

    def test_each_missing_report_fails_closed(self):
        for name in self.reports():
            with self.subTest(name=name):
                data = self.reports()
                data[name] = {}
                self.assertFalse(assessment.assess(**data)['passed'])

    def test_wrong_phase_duration_count_and_native_failure_codes_fail(self):
        for key, value in [('seconds',599), ('completed',5999), ('actualRate',8),
                           ('ldapResultCodes',{'81':6000}), ('name','burst')]:
            with self.subTest(key=key):
                phases = copy.deepcopy(self.reports()['generator']['phases'])
                phases[0][key] = value
                self.assertFalse(assessment.phase_checks(phases, windows=True))

    def test_matching_counts_cannot_hide_identity_mismatch(self):
        data = copy.deepcopy(self.reports())
        data['destination']['windowsCampaign']['identitySetSha256'] = 'b' * 64
        result = assessment.assess(**data)
        self.assertFalse(result['passed'])
        self.assertFalse(result['checks']['windowsDestination'])
        self.assertTrue(result['checks']['linuxDestination'])

    def test_partial_query_duplicates_privacy_and_missing_metrics_fail(self):
        for report, key, value in [('destination','partialError',True),
                                    ('wec','noIdentityCollisions',False),
                                    ('wec','databaseAndWalExcludeUsername',False),
                                    ('monitor','samples',[])]:
            data = copy.deepcopy(self.reports())
            data[report][key] = value
            self.assertFalse(assessment.assess(**data)['passed'])
        group = self.reports()['destination']['windowsCampaign']
        group['duplicateRows'] = 1
        self.assertFalse(assessment.destination_matches(group,59400,'a'*64))

    def test_probe_from_another_window_cannot_qualify_current_run(self):
        data = self.reports()
        data['source']['since'] = '2026-10-30T09:00:00Z'
        self.assertFalse(assessment.assess(**data)['passed'])
        self.assertTrue(assessment.same_window('2026-10-30T09:28:00Z', '2026-10-30T09:28:00.0000000+00:00'))
        self.assertFalse(assessment.same_window(None, None))

    def test_duplicate_observations_do_not_override_strict_failure(self):
        data = copy.deepcopy(self.reports())
        group = data['destination']['windowsCampaign']
        group.update(rows=59404, duplicateRows=4)
        report = assessment.assess(**data)
        self.assertFalse(report['passed'])
        self.assertFalse(report['checks']['windowsDestination'])
        self.assertTrue(report['destinationObservations']['windowsDistinctIdentitiesMatch'])
        self.assertEqual(report['destinationObservations']['windowsDuplicateRows'], 4)
        group['identitySetSha256'] = 'b' * 64
        self.assertFalse(assessment.assess(**data)['destinationObservations']['windowsDistinctIdentitiesMatch'])
        group['identitySetSha256'] = 'a' * 64
        group['duplicateRows'] = 3
        self.assertFalse(assessment.assess(**data)['destinationObservations']['windowsDistinctIdentitiesMatch'])

    def test_passed_label_cannot_override_short_outage_or_missing_check(self):
        data = copy.deepcopy(self.reports())
        data['monitor']['outageSeconds'] = 3599
        self.assertFalse(assessment.assess(**data)['passed'])
        data = copy.deepcopy(self.reports())
        del data['linux']['checks']['noSourceLoss']
        self.assertFalse(assessment.assess(**data)['passed'])

    def test_identical_ids_cannot_hide_different_or_missing_policies(self):
        for target in ['windowsCampaign', 'linuxCampaign', 'linuxTotal', 'wec']:
            for hashes in [None, [], ['sha256:'+'d'*64], ['sha256:'+'c'*64, 'sha256:'+'d'*64]]:
                with self.subTest(target=target, hashes=hashes):
                    data = copy.deepcopy(self.reports())
                    group = (data['wec'] if target == 'wec' else
                             data['destination']['groups']['network_connection_denied'] if target == 'linuxTotal' else
                             data['destination'][target])
                    group['policyHashes'] = hashes
                    self.assertFalse(assessment.assess(**data)['passed'])

    def test_matching_queue_and_destination_cannot_replace_the_pinned_profile(self):
        data = copy.deepcopy(self.reports())
        wrong = ['sha256:'+'d'*64]
        data['wec']['policyHashes'] = wrong
        data['destination']['windowsCampaign']['policyHashes'] = wrong
        self.assertFalse(assessment.assess(**data)['checks']['windowsPolicyProvenance'])

    def test_invalid_or_duplicate_policy_pins_fail_closed(self):
        for hashes in [None, [], 'sha256:'+'c'*64, [{}], ['not-a-hash'], ['sha256:'+'c'*64]*2]:
            with self.subTest(hashes=hashes):
                data = copy.deepcopy(self.reports())
                data['policies']['linux'] = hashes
                self.assertFalse(assessment.assess(**data)['passed'])
