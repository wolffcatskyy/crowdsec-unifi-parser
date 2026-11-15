"""Fast shape checks. Native CrowdSec replay remains the engine authority."""
import json
from pathlib import Path
import re
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / 'tests/fixtures/tcp_cases.json').read_text())
SCANS = ['iptables-scan-multi_ports', 'unifi-port-knock']

class ScenarioTests(unittest.TestCase):
    def test_scan_filters_and_fixtures(self):
        filters = [yaml.safe_load((ROOT / 'scenarios' / (n + '.yaml')).read_text())['filter'] for n in SCANS]
        self.assertEqual(filters[0], filters[1])
        self.assertTrue(filters[0].startswith("evt.Meta.log_type == 'iptables_drop' && evt.Meta.service == 'tcp' && "))
        pattern = filters[0].split("evt.Parsed.message matches '", 1)[1][:-1]
        # Python lacks POSIX classes. This translation checks fixtures only,
        # not CrowdSec expression syntax, RE2 semantics or parser behavior.
        pattern = pattern.replace('[[:space:]]', r'\s')
        for case in CASES:
            line = f"{case['prefix']} {case.get('description', '')}IN=eth6 OUT= SRC={case['source_ip']} DST=192.0.2.1 LEN=40 PROTO=TCP SPT=443 DPT=2000{case['sequence_fields']} WINDOW=1024 {case['flags']}"
            with self.subTest(case=case['name']):
                self.assertEqual(bool(re.search(pattern, line)), case['accept'])

    def test_thresholds_and_no_timer(self):
        flood = yaml.safe_load((ROOT / 'scenarios/unifi-flood-detection.yaml').read_text())
        self.assertNotIn('duration', flood)
        self.assertEqual((flood['capacity'], flood['leakspeed'], flood['blackhole']), (99, '30s', '5m'))
        for name, capacity, leak, blackhole in [(SCANS[0], 2, '5s', '1m'), (SCANS[1], 9, '1m', '2m')]:
            scenario = yaml.safe_load((ROOT / 'scenarios' / (name + '.yaml')).read_text())
            self.assertEqual((scenario['capacity'], scenario['leakspeed'], scenario['blackhole']), (capacity, leak, blackhole))
            self.assertEqual(scenario['distinct'], 'evt.Parsed.dst_port')
            self.assertEqual(scenario['groupby'], 'evt.Meta.source_ip')

if __name__ == '__main__':
    unittest.main()
