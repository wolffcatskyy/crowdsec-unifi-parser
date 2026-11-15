# Scenario regressions

Use a disposable configuration and hub, never a gateway or production CrowdSec
configuration. Install `tests/requirements.txt`, then run:

```sh
python -m unittest discover -s tests -v
python tests/run_scenario_replays.py \
  --hub /path/to/disposable/hub \
  --config /path/to/isolated/config.yaml \
  --cscli /path/to/cscli --crowdsec /path/to/crowdsec
```

The scratch hub must already contain its index, `crowdsecurity/iptables-logs`
and `crowdsecurity/dateparse-enrich` dependencies. The runner copies this repo's
parser/scenarios into that scratch hub and generates two native `cscli hubtest`
tests. It deletes old test results before each run, fails on engine errors, and
checks alerts per source, not only their total.

- Scan replay: 18 groups, 216 synthetic lines, 22 expected alerts, one per
  scenario for each of 11 SYN-set/ACK-unset groups. Includes native UniFi-style
  prefix with DESCR, optional kernel program prefix, ECN/AE, SYN+FIN, ACK
  replies, sequence ACK=n, options, and adversarial prefix words. Tabs and
  omitted RES are robustness fixtures, not claimed native kernel output.
- Flood replay: 308 lines. Isolated groups of 1/3/99 produce no alerts;
  sufficiently fast 100/105 bursts produce one each.

The issue's displayed log contains ellipses and is not replayable verbatim.
The native-format fixtures reconstruct that shape with complete fields, not
claimed captured production packets. Their source is issue #12 and Linux
`nf_log_dump_tcp_header` flag order:
https://github.com/wolffcatskyy/crowdsec-unifi-parser/issues/12
https://codebrowser.dev/linux/linux/net/netfilter/nf_log_syslog.c.html

Fast tests translate POSIX whitespace to Python syntax. They do not replace
native CrowdSec/RE2, parser or overflow tests. Full native replay was verified
with CrowdSec 1.8.2; 1.6.4 config validation with the exact filter passed, but
1.6.4 runtime replay and 1.4 compatibility were not verified.

Replay timestamps cannot test a live wall-clock expiry. A separate isolated
1.8.2 engine test shortened the old duration to 2s and leak interval to 10ms:
one event produced one timed overflow with duration and zero without it.
That is accelerated mechanism evidence, not a real 24-hour production run.
No live bans were cleared, gateway changed, or production decisions created.

Known boundary: the regex assumes kernel-format UniFi logs with operator-
controlled prefixes. A prefix forging a complete spaced WINDOW/flags/URGP
block can match. It is not an injection-proof parser. Missing/truncated flags
fail closed; NULL, FIN-only and Xmas scans are outside the SYN-only criterion.
