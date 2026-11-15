#!/usr/bin/env python3
"""Run actual CrowdSec scenarios in an explicitly supplied SCRATCH hub/config.

Writes candidate files and tests only inside --hub. Never use a production hub.
Requires PyYAML, installed hub iptables/dateparse parsers, cscli and crowdsec.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import shutil
import subprocess
import yaml

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--hub', required=True, type=Path, help='disposable hub clone, never /etc/crowdsec')
parser.add_argument('--config', required=True, type=Path, help='isolated test config')
parser.add_argument('--cscli', required=True, type=Path)
parser.add_argument('--crowdsec', required=True, type=Path)
args = parser.parse_args()
hub = args.hub.resolve()
if hub == Path('/etc/crowdsec') or Path('/etc/crowdsec') in hub.parents:
    parser.error('Refusing the production /etc/crowdsec tree')
if not (hub / '.index.json').is_file():
    parser.error('Scratch hub must contain .index.json and upstream parsers')
for stage, name in [('parsers/s00-raw', 'unifi-logs')]:
    dest = hub / stage / 'crowdsecurity' / (name + '.yaml')
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / stage / (name + '.yaml'), dest)
scenarios = ['iptables-scan-multi_ports', 'unifi-port-knock', 'unifi-flood-detection']
for name in scenarios:
    dest = hub / 'scenarios/crowdsecurity' / (name + '.yaml')
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / 'scenarios' / (name + '.yaml'), dest)

def run(name, lines, selected, expected, expected_parses):
    test = hub / '.tests' / name
    test.mkdir(parents=True, exist_ok=True)
    for folder in ['runtime', 'results']:
        shutil.rmtree(test / folder, ignore_errors=True)
    (test / 'sample.log').write_text(''.join(lines))
    config = {'parsers': ['./parsers/s00-raw/crowdsecurity/unifi-logs.yaml', 'crowdsecurity/iptables-logs', 'crowdsecurity/dateparse-enrich'], 'scenarios': ['./scenarios/crowdsecurity/' + n + '.yaml' for n in selected], 'postoverflows': [''], 'log_file': 'sample.log', 'log_type': 'unifi'}
    (test / 'config.yaml').write_text(yaml.safe_dump(config))
    (test / 'parser.assert').write_text(f'len(results["s01-parse"]["crowdsecurity/iptables-logs"]) == {expected_parses}\n')
    (test / 'scenario.assert').write_text(f'len(results) == {sum(expected.values())}\n')
    command = [str(args.cscli), '-c', str(args.config), 'hubtest', 'run', name, '--hub', str(hub), '--crowdsec', str(args.crowdsec), '--cscli', str(args.cscli), '--no-clean']
    result = subprocess.run(command, capture_output=True, text=True)
    (test / 'run.log').write_text(result.stdout + result.stderr)
    print(result.stdout + result.stderr)
    result.check_returncode()
    dump = yaml.safe_load((test / 'results/bucket-dump.yaml').read_text()) or []
    actual = Counter(ip for alert in dump for ip in alert['Overflow']['Sources'])
    assert actual == Counter({ip: count for ip, count in expected.items() if count}), (actual, expected)
    print(name, 'per-source alerts PASS', dict(actual))
    return test

cases = json.loads((ROOT / 'tests/fixtures/tcp_cases.json').read_text())
lines, expected = [], {}
for case in cases:
    expected[case['source_ip']] = 2 if case['accept'] else 0
    for port in range(2000, 2012):
        lines.append(f"2026-11-10T00:00:00+00:00 {case['prefix']} {case.get('description', '')}IN=eth6 OUT= SRC={case['source_ip']} DST=192.0.2.1 LEN=40 PROTO=TCP SPT=443 DPT={port}{case['sequence_fields']} WINDOW=1024 {case['flags']}\n")
scan = run('unifi-scan-regression', lines, scenarios[:2], expected, len(lines))
lines, expected = [], {}
for octet, count in enumerate([1, 3, 99, 100, 105], 41):
    ip = f'198.51.100.{octet}'
    expected[ip] = 1 if count >= 100 else 0
    for _ in range(count):
        lines.append(f'2026-11-10T00:00:00+00:00 UDM kernel: [UNIFI-WAN_LOCAL-D-ALL] IN=eth6 OUT= SRC={ip} DST=192.0.2.1 LEN=40 PROTO=UDP SPT=12345 DPT=9999\n')
flood = run('unifi-flood-regression', lines, scenarios[2:], expected, len(lines))
print('Replay-only: no production configuration, LAPI, decisions or gateway writes requested.')
print('Timer removal needs a separate wall-clock/source test. Timestamp gaps do not test wall-clock expiry.')
