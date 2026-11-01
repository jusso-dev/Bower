"""Exporting a failure checkpoint must not make it destination evidence."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('query_wec_checkpoint_guard', Path(__file__).resolve().parents[1] / 'monitoring/query-wec.py')
query = importlib.util.module_from_spec(spec)
spec.loader.exec_module(query)


class CheckpointQualificationRejectionTests(unittest.TestCase):
    def test_checkpoint_is_not_a_full_phase(self):
        checkpoint = {'recordType': 'generator-checkpoint', 'runId': 'bower-ws6-20261101-010101',
                      'phase': 'failed-phase', 'mode': 'diagnostic', 'generator': {'completed': 0},
                      'nativeVerified': False, 'destinationQueryVerified': False, 'deliveryQualified': False}
        with self.assertRaises((KeyError, ValueError)):
            query.source_evidence(checkpoint, {}, {}, {})

    def test_export_manifest_is_not_a_full_phase(self):
        manifest = {'schemaVersion': 1, 'recordType': 'wec-evidence-export', 'runId': 'bower-ws6-20261101-010101',
                    'phase': 'failed-phase', 'partialEvidence': True, 'checkpointOnly': True,
                    'missingPhaseFiles': ['failed-phase.json', 'failed-phase-native.ids', 'failed-phase-forwarded.ids', 'failed-phase-queue.ids'],
                    'deliveryQualified': False, 'destinationQueryVerified': False}
        with self.assertRaises((KeyError, ValueError)):
            query.source_evidence(manifest, {}, {}, {})


if __name__ == '__main__':
    unittest.main()
