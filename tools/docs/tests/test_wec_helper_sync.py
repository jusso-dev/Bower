"""Keep the copyable PowerShell 5.1 runbook helpers aligned with both lab samplers."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNBOOK = ROOT / 'docs/production-readiness/07-soak-and-release-validation.md'
SAMPLERS = (ROOT / 'lab/aws/soak/wec-agent.ps1', ROOT / 'lab/aws/wecfix/wec-agent.ps1')
HELPERS = ('Get-ReceivingBookmarkRecordId', 'Get-ReceivingPositionState')
BASIS = 'native-receiving-bookmark-v1'


def helper_lines(path, name):
    lines = path.read_text(encoding='utf-8').splitlines()
    pattern = re.compile(r'^([ \t]*)function\s+' + re.escape(name) + r'\s*\(')
    starts = [(index, match.group(1)) for index, line in enumerate(lines) if (match := pattern.match(line))]
    if len(starts) != 1:
        raise ValueError(f'{path.name}: expected exactly one {name} helper')
    start, indent = starts[0]
    for end in range(start + 1, len(lines)):
        if lines[end] == indent + '}':
            return tuple(line.strip() for line in lines[start:end + 1] if line.strip())
    raise ValueError(f'{path.name}: helper {name} has no closing brace')


class WecHelperSyncTests(unittest.TestCase):
    def test_runbook_helpers_match_both_samplers(self):
        for name in HELPERS:
            expected = helper_lines(RUNBOOK, name)
            for sampler in SAMPLERS:
                with self.subTest(helper=name, sampler=sampler.name, directory=sampler.parent.name):
                    self.assertEqual(expected, helper_lines(sampler, name))

    def test_runbook_and_samplers_emit_compatible_position_metadata(self):
        for path in (RUNBOOK, *SAMPLERS):
            with self.subTest(path=path):
                source = path.read_text(encoding='utf-8')
                bases = re.findall(r"\bnewestRecordIdBasis\s*=\s*'([^']+)'", source)
                self.assertEqual([BASIS], bases)
                observed = {}
                for field, helper in (('newestRecordId', 'Get-ReceivingBookmarkRecordId'),
                                      ('newestRecordIdState', 'Get-ReceivingPositionState')):
                    values = re.findall(r'\b' + field + r'\s*=\s*(\$[A-Za-z_][A-Za-z0-9_]*)', source)
                    self.assertEqual(1, len(values), f'{path.name}: expected one {field} assignment')
                    observed[field] = values[0]
                    assignment = re.compile(r'^\s*' + re.escape(values[0]) + r'\s*=\s*' + helper + r'\b', re.MULTILINE)
                    self.assertEqual(1, len(assignment.findall(source)), f'{path.name}: {field} is not supplied by {helper}')
                counts = re.findall(r'\b(?:records|forwarded)\s*=\s*(\$[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)', source)
                self.assertEqual(1, len(counts), f'{path.name}: expected one record-count field')
                state_call = re.compile(r'^\s*' + re.escape(observed['newestRecordIdState'])
                    + r'\s*=\s*Get-ReceivingPositionState\s+(\$[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)'
                    + r'\s+(\$[A-Za-z_][A-Za-z0-9_]*)\s*$', re.MULTILINE)
                self.assertEqual([(counts[0], observed['newestRecordId'])], state_call.findall(source),
                                 f'{path.name}: position state must use the exported count and position')


if __name__ == '__main__':
    unittest.main()
