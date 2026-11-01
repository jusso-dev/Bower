"""Offline ownership/authentication checks; never contacts Azure."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('qualify_azure', Path(__file__).with_name('qualify-azure.py'))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class AzureQualificationOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.evidence = Path(self.tmp.name)
        self.state = {'runId': 'bower-kql-20261101-010101-1234abcd', 'group': 'bower-kql-20261101-010101-1234abcd'}

    def test_existing_group_is_never_adopted_or_retagged(self):
        with mock.patch.object(lab, 'az', return_value=True) as az:
            with self.assertRaisesRegex(RuntimeError, 'already exists'):
                lab.create_owned_group(self.state, self.evidence)
        self.assertEqual(1, az.call_count)
        self.assertNotIn('groupCreationAttempted', self.state)

    def test_attempt_is_durable_before_conditional_create(self):
        def az(*args):
            if args[:2] == ('group', 'exists'):
                return False
            if args[:3] == ('rest', '--method', 'put'):
                self.assertTrue(json.loads((self.evidence / 'state.json').read_text())['groupCreationAttempted'])
                self.assertIn('If-None-Match=*', args)
                return {}
            if args[:2] == ('group', 'show'):
                return {'tags': {'Project': 'bower-lab', 'RunId': self.state['runId']}}
            raise AssertionError(args[:2])
        with mock.patch.object(lab, 'az', side_effect=az):
            lab.create_owned_group(self.state, self.evidence)

    def test_failed_name_preflight_cannot_delete_even_same_tagged_group(self):
        with mock.patch.object(lab, 'verify_account'), mock.patch.object(lab, 'az', return_value=True) as az:
            with self.assertRaisesRegex(RuntimeError, 'never attempted'):
                lab.cleanup(self.state, self.evidence)
        self.assertFalse(any(call.args[:2] == ('group', 'delete') for call in az.call_args_list))

    def test_wrong_tags_block_cleanup(self):
        self.state['groupCreationAttempted'] = True
        with mock.patch.object(lab, 'verify_account'), mock.patch.object(lab, 'az', side_effect=[True, {'tags': {'Project': 'shared'}}]) as az:
            with self.assertRaisesRegex(RuntimeError, 'ownership mismatch'):
                lab.cleanup(self.state, self.evidence)
        self.assertFalse(any(call.args[:2] == ('group', 'delete') for call in az.call_args_list))

    def test_wrong_active_tenant_blocks_graph_and_rest_operations(self):
        with mock.patch.object(lab, 'az', side_effect=[{'id': lab.SUB, 'tenantId': lab.TENANT}, {'tenantId': 'other'}]):
            with self.assertRaisesRegex(RuntimeError, 'Unexpected Azure account'):
                lab.verify_account()

    def role_state(self):
        self.state['groupCreationAttempted'] = True
        scope = '/subscriptions/' + lab.SUB + '/resourceGroups/' + self.state['group']
        scope += '/providers/Microsoft.Insights/dataCollectionRules/qualification-dcr'
        self.state.update(dcrId=scope, ingestionPrincipalId='11111111-1111-4111-8111-111111111111',
                          ingestionRoleCreationAttempted=True)
        return {'id': scope + '/providers/Microsoft.Authorization/roleAssignments/22222222-2222-4222-8222-222222222222',
                'scope': scope, 'principalId': self.state['ingestionPrincipalId']}

    def test_interrupted_role_creation_is_reconciled_without_touching_shared_grants(self):
        owned = self.role_state()  # Lost creation response: no recorded assignment ID.
        shared = {'id': '/subscriptions/' + lab.SUB + '/providers/Microsoft.Authorization/roleAssignments/shared',
                  'scope': '/subscriptions/' + lab.SUB, 'principalId': self.state['ingestionPrincipalId']}
        grants = [owned, shared]
        group_present = [True]
        deleted = []

        def az(*args):
            if args[:2] == ('group', 'exists'):
                return group_present[0]
            if args[:2] == ('group', 'show'):
                return {'tags': {'Project': 'bower-lab', 'RunId': self.state['runId']}}
            if args[:2] == ('group', 'delete'):
                group_present[0] = False
                return None
            if args[:3] == ('role', 'assignment', 'list'):
                return grants.copy()
            if args[:3] == ('role', 'assignment', 'delete'):
                identity = args[args.index('--ids') + 1]
                self.assertEqual(owned['id'], identity)
                deleted.append(identity)
                grants.remove(owned)
                return None
            raise AssertionError(args[:3])
        with mock.patch.object(lab, 'verify_account'), mock.patch.object(lab, 'az', side_effect=az):
            lab.cleanup(self.state, self.evidence)
        report = json.loads((self.evidence / 'cleanup.json').read_text())
        self.assertTrue(report['resourceGroupAbsent'])
        self.assertTrue(report['ingestionRoleAssignmentAbsent'])
        self.assertEqual([owned['id']], deleted)
        self.assertEqual([shared], grants)

    def test_remaining_role_blocks_cleanup_success_even_when_group_is_absent(self):
        owned = self.role_state()
        def az(*args):
            if args[:2] == ('group', 'exists'):
                return False
            if args[:3] == ('role', 'assignment', 'list'):
                return [owned]
            if args[:3] == ('role', 'assignment', 'delete'):
                return None  # Simulate successful command with an assignment still visible.
            raise AssertionError(args[:3])
        with mock.patch.object(lab, 'verify_account'), mock.patch.object(lab, 'az', side_effect=az):
            with self.assertRaisesRegex(RuntimeError, 'not verified absent'):
                lab.cleanup(self.state, self.evidence)
        report = json.loads((self.evidence / 'cleanup.json').read_text())
        self.assertTrue(report['resourceGroupAbsent'])
        self.assertFalse(report['ingestionRoleAssignmentAbsent'])

    def test_recorded_assignment_outside_owned_dcr_is_rejected_before_listing(self):
        self.role_state()
        self.state['ingestionRoleAssignmentId'] = '/subscriptions/' + lab.SUB + '/providers/Microsoft.Authorization/roleAssignments/22222222-2222-4222-8222-222222222222'
        with mock.patch.object(lab, 'az') as az, self.assertRaisesRegex(RuntimeError, 'ownership mismatch'):
            lab.owned_user_grants(self.state)
        az.assert_not_called()


if __name__ == '__main__':
    unittest.main()
