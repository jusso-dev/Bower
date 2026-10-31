"""Guards in the credential and syslog security campaign scripts (no cloud or root needed)."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1]/'scripts'/file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lab = load('credential_lab', 'credential-failure-lab.py')
adversarial = load('syslog_adversarial', 'syslog-adversarial.py')
rotation = load('syslog_rotation', 'syslog-tls-rotation.py')


class CredentialLabTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        with open(os.path.join(self.directory.name, 'lab.json'), 'w') as handle:
            json.dump({'runId': 'bower-test-1', 'tenantId': 't', 'dceEndpoint': 'https://x', 'dcrImmutableId': 'dcr-1',
                       'streamName': 'Custom-BowerSecurity', 'apps': {'publisher': 'p'}}, handle)
        self.lab = lab.Lab(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def test_ports_are_stable_and_bounded(self):
        self.assertEqual(self.lab.port('revoke'), self.lab.port('revoke'))
        self.assertTrue(all(4400 <= self.lab.port(name) < 4700 for name in ('a', 'expire-fresh', 'role')))

    def test_case_names_cannot_escape_the_work_directory(self):
        for name in ('../x', 'A', '', 'x/y'):
            with self.assertRaises(SystemExit):
                self.lab.case_dir(name)

    def test_run_id_must_be_owned(self):
        with open(os.path.join(self.directory.name, 'lab.json'), 'w') as handle:
            json.dump({'runId': 'production'}, handle)
        with self.assertRaises(SystemExit):
            lab.Lab(self.directory.name)

    def test_jwt_shaped_strings_are_detected(self):
        self.assertEqual(len(lab.JWT.findall(b'x eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig')), 1)
        self.assertEqual(lab.JWT.findall(b'eyJ short'), [])


class SyslogScriptTests(unittest.TestCase):
    def test_frames_are_octet_counted_and_carry_the_sequence_address(self):
        frame = adversarial.frame(258, b'msg')
        self.assertIn(b'SRC=10.200.1.2 ', frame)
        counted = adversarial.octet(frame)
        length, body = counted.split(b' ', 1)
        self.assertEqual(int(length), len(body))

    def test_secret_markers_are_synthetic(self):
        self.assertIn('EXAMPLE', adversarial.SECRETS['aws'])
        self.assertTrue(all(value for value in adversarial.SECRETS.values()))

    def test_rotation_ca_config_keeps_name_and_purpose_constraints(self):
        config = rotation.CA_CONFIG.format(dir='/x')
        self.assertIn('extendedKeyUsage = clientAuth', config)
        self.assertIn('subjectAltName = DNS:collector.lab,IP:127.0.0.1', config)
        self.assertIn('StreamDriverAuthMode="x509/name"', rotation.RSYSLOG)


if __name__ == '__main__':
    unittest.main()
