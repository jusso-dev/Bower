import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1] / 'upgrade-recovery'
spec = importlib.util.spec_from_file_location('upgrade_expected', ROOT / 'expected.py')
expected = importlib.util.module_from_spec(spec)
spec.loader.exec_module(expected)


class ExpectedSyslogIdentityTests(unittest.TestCase):
    def test_reproduces_ids_the_collector_queued(self):
        # Observed in the dev.264 queue during run bower-ws4-20261031-074918 (stream s1).
        base = '2026-10-31T08:38:54Z'
        self.assertEqual(expected.event_id('s1', base, 10, 0), 'syslog-f35d3838c5315f6594f8c03a2225bf9d')
        self.assertEqual(expected.event_id('s1', base, 10, 1), 'syslog-d032ed6ab4e651ca1fe7151f161b2eef')

    def test_frames_are_deterministic_and_stream_scoped(self):
        base = '2026-10-31T08:38:54Z'
        self.assertEqual(expected.frame('s1', base, 10, 7), expected.frame('s1', base, 10, 7))
        self.assertNotEqual(expected.event_id('s1', base, 10, 7), expected.event_id('s1b', base, 10, 7))
        self.assertNotEqual(expected.event_id('s1', base, 10, 7, sender='127.0.0.1'), expected.event_id('s1', base, 10, 7))
        self.assertIn(b'SEQ=7', expected.frame('s1', base, 10, 7))


if __name__ == '__main__':
    unittest.main()
