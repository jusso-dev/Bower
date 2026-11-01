import importlib.util
import argparse
import copy
import json
import re
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("monitoring_syslog_plan", Path(__file__).resolve().parents[1] / "monitoring/syslog-plan.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MonitoringSyslogPlanTests(unittest.TestCase):
    def native_rule_ranges(self):
        # Execute the real fixture renderer with every host command mocked. This
        # catches drift between planner bounds and the deployed firewall rules.
        source = Path(__file__).resolve().parents[1] / 'scripts/syslog-host.py'
        host_spec = importlib.util.spec_from_file_location('syslog_host_rule_fixture', source)
        host = importlib.util.module_from_spec(host_spec)
        host_spec.loader.exec_module(host)
        with tempfile.TemporaryDirectory() as directory, patch.object(host, 'LAB', Path(directory)), \
             patch.object(host, 'sh', return_value=''), \
             patch.object(host.subprocess, 'run', return_value=SimpleNamespace(returncode=1)):
            host.netns_up()
            rules = (Path(directory) / 'validation.nft').read_text()
        return {track: (int(first), int(last)) for first, last, track in
                re.findall(r'udp dport ([0-9]+)-([0-9]+) counter log prefix "BOWER_DENY ([AB]) "', rules)}

    def test_native_fixture_has_disjoint_fifty_port_tracks(self):
        ranges = self.native_rule_ranges()
        self.assertEqual({'A': (4400, 4449), 'B': (4450, 4499)}, ranges)
        self.assertEqual(2000000, module.SEQUENCE_LIMIT)
        # The first excluded Track A identity would hit Track B's rule.
        self.assertEqual(ranges['B'][0], ranges['A'][0] + module.SEQUENCE_LIMIT // 40000)
        with self.assertRaises(ValueError):
            module.shifted_first(module.SEQUENCE_LIMIT, 1, 0)

    def scenario(self):
        return {"name": "b-idle-gaps", "number": 30, "duration": 3980, "settle": 1200,
                "before": [], "after": [], "steps": [
                    {"at": 0, "host": "SenderR", "unit": "idle-first",
                     "args": "generate --kind nft --track B --first 600000 --count 100 --rate 10 --label idle-first"},
                    {"at": 3915, "host": "SenderR", "unit": "idle-last",
                     "args": "generate --kind nft --track B --first 600100 --count 6000 --rate 100 --label idle-last"}],
                "measure": [("CollectorB", "b13i,b13n,b12i", "nft:B:600000:100", "before-gap"),
                            ("CollectorB", "b13i,b13n,b12i", "nft:B:600100:6000", "after-gap")]}

    def build(self, scenario, offset=0):
        return module.plan({"b-idle-gaps": scenario}, "b-idle-gaps", Path("/reviewed/scripts"),
                           Path("/owned/state.json"), "10.0.1.10", "10.0.1.11", 2_000_000_000.0, offset)

    def arguments(self, command):
        return shlex.split(next(value[len('BOWER_ARGS='):] for value in command if value.startswith('BOWER_ARGS=')))

    def test_one_collector_adapter_keeps_idle_duration_and_exact_expected_ranges(self):
        source = self.scenario()
        result = self.build(source)
        self.assertEqual([0, 3915], [s["offsetSeconds"] for s in result["steps"]])
        self.assertEqual(2_000_003_980.0, result["collectNotBeforeEpoch"])
        self.assertEqual(["nft:A:600000:100", "nft:A:600100:6000"], result["expectedBlocks"])
        for step in result["steps"]:
            self.assertEqual("Sender", step["command"][2])
            self.assertIn("BOWER_LAB_HOST=SenderR", step["command"])
            self.assertIn("--track A", " ".join(step["command"]))
        measurements = [c for c in result["collect"] if c["kind"] == "queue-acceptance-only"]
        for measurement in measurements:
            self.assertEqual("Linux", measurement["command"][2])
            self.assertIn("--listeners a13", " ".join(measurement["command"]))
        self.assertFalse(result["sentinelQualified"])
        self.assertEqual(0, result["sequenceOffset"])
        self.assertEqual("b13i,b13n,b12i", source["measure"][0][1])

    def test_fault_peer_is_only_the_owned_sender(self):
        source = self.scenario()
        source["steps"] = [{"at": 30, "host": "CollectorA", "unit": "blackhole",
                            "args": "fault --action blackhole --duration 120 --peers 10.0.1.11,10.0.1.12"}]
        command = " ".join(self.build(source)["steps"][0]["command"])
        self.assertIn("--peers 10.0.1.11 --at", command)
        self.assertNotIn("10.0.1.12", command)

    def test_unsupported_hosts_and_configuration_changes_fail_closed(self):
        for change in ("host", "before", "after"):
            source = self.scenario()
            if change == "host":
                source["steps"][0]["host"] = "SenderG"
            else:
                source[change] = [("SenderR", "configure-rsyslog --profile pilot")]
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.build(source)

    def test_every_real_scenario_shifts_generators_and_all_measurements_consistently(self):
        source = Path(__file__).resolve().parents[1] / 'scripts'
        catalogue = module.load_catalogue(source, '10.0.1.10', '10.0.1.11')
        original = copy.deepcopy(catalogue)
        offset = 900000
        rule_start, rule_end = self.native_rule_ranges()['A']
        self.assertEqual((4400, 4449), (rule_start, rule_end))
        self.assertEqual((rule_end - rule_start + 1) * 40000, module.SEQUENCE_LIMIT)
        final_ranges = []
        for name in module.SCENARIOS:
            with self.subTest(scenario=name):
                base = module.plan(catalogue, name, source, Path('/owned/state.json'), '10.0.1.10', '10.0.1.11', 2_000_000_000.0)
                shifted = module.plan(catalogue, name, source, Path('/owned/state.json'), '10.0.1.10', '10.0.1.11', 2_000_000_000.0, offset)
                self.assertEqual(offset, shifted['sequenceOffset'])
                self.assertEqual(base['collectNotBeforeEpoch'], shifted['collectNotBeforeEpoch'])
                self.assertEqual(len(base['generations']), len(shifted['generations']))
                for old, new in zip(base['generations'], shifted['generations']):
                    self.assertEqual(dict(old, first=old['first'] + offset), new)
                    first, end = new['first'], new['first'] + new['count']
                    self.assertGreaterEqual(rule_start + first // 40000, rule_start)
                    self.assertLessEqual(rule_start + (end - 1) // 40000, rule_end)
                    final_ranges.append((first, end))
                    for baseline_first, baseline_end in ((200000, 200600), (800000, 806000)):
                        self.assertTrue(end <= baseline_first or first >= baseline_end)
                for old, new in zip(base['steps'], shifted['steps']):
                    expected = self.arguments(old['command'])
                    if expected[0] == 'generate':
                        index = expected.index('--first') + 1
                        expected[index] = str(int(expected[index]) + offset)
                    self.assertEqual(expected, self.arguments(new['command']))
                expected_blocks = []
                for block in base['expectedBlocks']:
                    _, _, first, count = block.split(':')
                    expected_blocks.append('nft:A:{}:{}'.format(int(first) + offset, count))
                self.assertEqual(expected_blocks, shifted['expectedBlocks'])
                measured = []
                for measurement in shifted['collect']:
                    if measurement['kind'] == 'queue-acceptance-only':
                        arguments = self.arguments(measurement['command'])
                        measured.extend(arguments[arguments.index('--blocks') + 1].split('+'))
                self.assertEqual(expected_blocks, measured)
        self.assertEqual(original, catalogue)
        ordered = sorted(final_ranges)
        for previous, following in zip(ordered, ordered[1:]):
            self.assertLessEqual(previous[1], following[0], 'final campaign native identity ranges overlap')

    def test_multi_block_measurement_preserves_each_range(self):
        scenario = self.scenario()
        blocks = '+'.join(measure[2] for measure in scenario['measure'])
        scenario['measure'] = [('CollectorB', 'b13i', blocks)]
        plan = self.build(scenario, 900000)
        self.assertEqual(['nft:A:1500000:100', 'nft:A:1500100:6000'], plan['expectedBlocks'])
        measure = next(item for item in plan['collect'] if item['kind'] == 'queue-acceptance-only')
        arguments = self.arguments(measure['command'])
        self.assertEqual('+'.join(plan['expectedBlocks']), arguments[arguments.index('--blocks') + 1])

    def test_supported_port_boundary_and_overflow(self):
        last_end = 600100 + 6000
        offset = module.SEQUENCE_LIMIT - last_end
        plan = self.build(self.scenario(), offset)
        last = plan['generations'][-1]
        final_index = last['first'] + last['count'] - 1
        self.assertEqual(4449, 4400 + final_index // 40000)
        self.assertEqual(59999, 20000 + final_index % 40000)
        with self.assertRaises(ValueError):
            self.build(self.scenario(), offset + 1)
        scenario = self.scenario()
        scenario['measure'][0] = ('CollectorB', 'b13i', 'nft:A:{}:2'.format(module.SEQUENCE_LIMIT - 1))
        with self.assertRaises(ValueError):
            self.build(scenario)

    def test_invalid_offsets_counts_and_duplicate_generator_options_rejected(self):
        for offset in (-1, 1.5, True, '3', module.SEQUENCE_LIMIT, 10000000, 10 ** 100):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.build(self.scenario(), offset)
        for raw in ('-1', '+1', '1.0', '1e7', '', '10000000', str(module.SEQUENCE_LIMIT)):
            with self.subTest(raw=raw), self.assertRaises(argparse.ArgumentTypeError):
                module.parse_sequence_offset(raw)
        self.assertEqual(0, module.parse_sequence_offset('0'))
        self.assertEqual(900000, module.parse_sequence_offset('900000'))
        for suffix in (' --first 10', ' --count 20'):
            scenario = self.scenario()
            scenario['steps'][0]['args'] += suffix
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                self.build(scenario)
        for count in (0, module.MAX_BLOCK_COUNT + 1):
            with self.subTest(count=count), self.assertRaises(ValueError):
                module.shifted_first(0, count, 0)

    def test_cli_freezes_offset_without_cloud_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state.json'
            state.write_text(json.dumps({'runId': 'bower-ws6-20261101-010101', 'outputs': {'LinuxIp': '10.0.1.10', 'SenderIp': '10.0.1.11'}}))
            command = [sys.executable, str(Path(module.__file__)), 'a-steady', '--source',
                       str(Path(__file__).resolve().parents[1] / 'scripts'), '--state', str(state),
                       '--collector-ip', '10.0.1.10', '--sender-ip', '10.0.1.11',
                       '--start-epoch', str(time.time() + 1000), '--sequence-offset', '900000']
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            plan = json.loads(result.stdout)
            self.assertEqual(900000, plan['sequenceOffset'])
            self.assertEqual(['nft:A:1100000:600'], plan['expectedBlocks'])
            self.assertEqual(1100000, plan['generations'][0]['first'])
            command[-1] = '10000000'
            rejected = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(0, rejected.returncode)
            self.assertEqual('', rejected.stdout)
            self.assertIn('Track A firewall rule identity space', rejected.stderr)


if __name__ == "__main__":
    unittest.main()
