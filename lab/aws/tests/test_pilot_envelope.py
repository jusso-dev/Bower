"""Qualification must reject incomplete traffic, source loss and insufficient outage."""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('pilot', Path(__file__).parents[1]/'scripts/pilot-native-linux.py')
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)


class PilotEnvelopeTests(unittest.TestCase):
    def assess(self, **changes):
        values = dict(failure=None, phases=[{'rate':10,'actualRate':10}]*5,
                      sent=59400, native=59400, accepted=59400, outage_seconds=3600,
                      backlog=41400, drain_seconds=90, dead_letters=0,
                      all_acknowledged=True, integrity=True, sampling_errors=[])
        values.update(changes)
        return pilot.qualification_checks(**values)

    def test_complete_envelope_can_pass(self):
        self.assertTrue(all(self.assess().values()))

    def test_uploaded_events_do_not_hide_source_loss(self):
        self.assertFalse(self.assess(accepted=59399)['noSourceLoss'])
        self.assertFalse(self.assess(native=59399)['nativePacketCount'])

    def test_shortened_outage_and_partial_backlog_fail(self):
        self.assertFalse(self.assess(outage_seconds=3599.9)['outageAtLeastOneHour'])
        self.assertFalse(self.assess(backlog=41399)['backlogRetained'])

    def test_missing_or_late_drain_cannot_pass(self):
        for value in [None,-1,600.001]:
            with self.subTest(value=value):
                self.assertFalse(self.assess(drain_seconds=value)['backlogDrainedWithinTenMinutes'])

    def test_no_traffic_or_missing_observations_cannot_pass(self):
        self.assertFalse(all(self.assess(sent=0,native=0,accepted=0,phases=[]).values()))
        self.assertFalse(all(self.assess(sampling_errors=['TimeoutError']).values()))
        self.assertFalse(all(self.assess(failure='TimeoutError').values()))

    def test_dead_letters_and_unacknowledged_events_fail(self):
        self.assertFalse(all(self.assess(dead_letters=1).values()))
        self.assertFalse(all(self.assess(all_acknowledged=False).values()))

    def test_insufficient_generator_rate_fails(self):
        self.assertFalse(self.assess(phases=[{'rate':100,'actualRate':80}]*5)['generatedAtTargetRate'])

    def test_empty_queue_waits_for_upstream_sender_and_then_acknowledgement(self):
        samples = iter([(set(),set()), ({'a','b'},{'a'}), ({'a','b'},{'a','b'})])
        current = None
        def read(delivered_only=False):
            nonlocal current
            if not delivered_only:
                current = next(samples)
            return current[1 if delivered_only else 0]
        with mock.patch.object(pilot,'identity_rows',side_effect=read), mock.patch.object(pilot.time,'sleep') as sleep:
            self.assertTrue(pilot.wait_for_population(2,settle_seconds=3))
            self.assertEqual(sleep.call_count,2)

    def test_never_arriving_source_population_has_a_bounded_failure(self):
        with mock.patch.object(pilot,'identity_rows',return_value=set()), mock.patch.object(pilot.time,'sleep') as sleep:
            self.assertFalse(pilot.wait_for_population(1,settle_seconds=2))
            self.assertEqual(sleep.call_count,2)
