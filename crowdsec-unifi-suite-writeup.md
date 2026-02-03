My desktop# The Missing CrowdSec Integration for UniFi: A Complete Security Suite

**Three open-source projects that turn a UniFi Dream Machine into an active threat detection and response system.**

---

## The Problem Nobody Talks About

UniFi is arguably the most popular prosumer and SMB network platform on the planet. Millions of Dream Machines sit at the edge of home labs, small offices, and branch networks. They have decent firewall rules. They block what you tell them to block.

And that is where it ends.

UniFi Dream Machines drop packets silently. There is no log entry when something gets blocked. There is no record of the port scan that hit your WAN interface at 3 AM. There is no alert when someone hammers your SSH port for the 400th time. The firewall does its job, but it does it in the dark.

Meanwhile, CrowdSec -- the open-source, crowd-powered security engine -- has parsers for pfSense, OPNsense, iptables, nginx, and dozens of other platforms. But for UniFi? Nothing. Zero. The [CrowdSec Hub](https://hub.crowdsec.net/) has no parser, no collection, no scenario for UniFi devices. If you point CrowdSec at raw UniFi syslog, you get this:

```
INFO  crowdsec   : 0 parsed / 47,231 unparsed
```

Zero percent parse rate. The raw syslog stream is 99% noise: kernel link-state changes, camera discovery, controller chatter, firmware messages. The firewall events you actually care about? They don't exist unless you create them.

## The Solution: Three Projects, One Feedback Loop

[**wolffcatskyy**](https://github.com/wolffcatskyy) built three tools that, together, close every gap between UniFi and CrowdSec. Each one solves a distinct problem. Together, they create a complete **detect -> decide -> enforce** feedback loop.

```
                         THE COMPLETE FEEDBACK LOOP
                         ==========================

   +------------------+                              +------------------+
   |                  |         syslog (UDP 514)     |                  |
   |   UniFi Dream    | ---------------------------> |   Syslog Server  |
   |   Machine        |                              |   (rsyslog)      |
   |                  |                              |                  |
   |   iptables LOG   |                              |   /var/log/unifi |
   |   rules inject   |                              |   /unifi-fw.log  |
   |   clean entries  |                              |                  |
   +--------+---------+                              +--------+---------+
            ^                                                 |
            |                                                 | file acquisition
            |                                                 v
            |                                        +------------------+
            |                                        |                  |
            |          crowdsec-unifi-bouncer         |    CrowdSec     |
            +--------------------------------------- |                  |
               pushes ban decisions back             |  unifi-logs      |
               as iptables/ipset rules               |  parser (s00)    |
               on the UDM itself                     |  iptables-logs   |
                                                     |  parser (s01)    |
                                                     |  dropbear parser |
                                                     |  port scan       |
                                                     |  scenario        |
                                                     |                  |
                                                     +--------+---------+
                                                              |
                                                              | LAPI decisions
                                                              v
                                                     +------------------+
                                                     |                  |
                                                     | crowdsec-        |
                                                     | blocklist-import |
                                                     |                  |
                                                     | 28 threat feeds  |
                                                     | 60,000+ IPs     |
                                                     | daily refresh    |
                                                     +------------------+

   DETECT (parser)  ───>  DECIDE (CrowdSec engine)  ───>  ENFORCE (bouncer)
        │                                                        │
        └────────────────── complete loop ───────────────────────┘
```

---

## 1. crowdsec-unifi-parser -- Visibility

**Repository:** [github.com/wolffcatskyy/crowdsec-unifi-parser](https://github.com/wolffcatskyy/crowdsec-unifi-parser)

This is the foundation. Without logs, there is nothing to detect.

### What it does

The parser project takes a different approach than trying to wrangle UniFi's noisy default syslog. Instead, it **injects clean, structured log entries** directly into the kernel log by deploying iptables LOG rules on the UDM via SSH.

A Python script (`deploy-log-rules.py`) connects to the UDM over SSH using paramiko, enumerates every DROP rule across seven WAN-facing chains, and inserts a corresponding LOG rule immediately before each one. The result is clean, tagged entries that CrowdSec can parse with near-100% accuracy.

### Before and after

**Before** (raw UniFi syslog -- what CrowdSec sees):
```
Jan 15 03:22:01 UDM kernel: [14923.456] br0: port 3(eth2) entered forwarding state
Jan 15 03:22:01 UDM kernel: [14923.789] device eth4 left promiscuous mode
Jan 15 03:22:02 UDM ubios-udapi-server[1234]: some controller noise
Jan 15 03:22:03 UDM kernel: [14924.012] random firmware message
```

CrowdSec result: `0 parsed / 4 unparsed`. No firewall events. No source IPs. Nothing actionable.

**After** (with LOG rules deployed):
```
Feb  1 14:23:45 UDM kernel: [UNIFI-WAN_LOCAL-D-INVALID] IN=eth4 OUT= MAC=xx:xx:xx
    SRC=185.220.101.42 DST=192.168.1.1 LEN=40 TOS=0x00 TTL=243 ID=54321
    PROTO=TCP SPT=54321 DPT=22 WINDOW=1024 SYN
```

CrowdSec result:
```
line: Feb  1 14:23:45 UDM kernel: [UNIFI-WAN_LOCAL-D-INVALID] IN=eth4 ...
        ├ s00-raw/unifi-logs        ✅ success
        └ s01-parse/iptables-logs   ✅ success
                ├ meta.source_ip     185.220.101.42
                ├ meta.log_type      iptables_drop
                ├ meta.dst_zone      LOCAL
                └ meta.action        drop
```

Every dropped packet now has a source IP, destination, port, protocol, zone, and action -- all extracted and ready for CrowdSec scenarios.

### Chains covered

| Chain | Direction | What it catches |
|-------|-----------|-----------------|
| `UBIOS_WAN_LOCAL_USER` | WAN -> Router | SSH scans, management probes |
| `UBIOS_WAN_LAN_USER` | WAN -> LAN | Inbound attacks to LAN hosts |
| `UBIOS_WAN_IN_USER` | WAN -> Internal | Port forwards, NAT traversal attempts |
| `UBIOS_WAN_DMZ_USER` | WAN -> DMZ | DMZ-targeted attacks |
| `UBIOS_WAN_GUEST_USER` | WAN -> Guest | Guest network probes |
| `UBIOS_WAN_VPN_USER` | WAN -> VPN | VPN endpoint attacks |
| `UBIOS_WAN_WAN_USER` | WAN -> WAN | Transit traffic drops |

### The deploy script

The deploy script is careful and idempotent. It cleans up any existing `CROWDSEC_LOG` rules first (safe to re-run after firmware updates), inserts from bottom to top to preserve rule indices, rate-limits LOG output to 10/min burst 20 to prevent flooding during scans, and supports dry-run mode to preview changes.

```bash
# Deploy LOG rules to your UDM
pip3 install paramiko
python3 deploy-log-rules.py --host 192.168.1.1 --user root --pass YOUR_PASSWORD

# Preview without touching iptables
python3 deploy-log-rules.py --host 192.168.1.1 --pass YOUR_PASSWORD --dry-run
```

### Parsers included

The project ships four CrowdSec parsers that form a complete parsing pipeline:

**s00-raw/unifi-logs.yaml** -- Raw syslog parser. Matches UniFi's syslog format, extracts the tagged prefix (`[UNIFI-WAN_LOCAL-D-INVALID]`), and maps the action code (`D` = drop, `R` = reject, `A` = accept) to human-readable metadata:

```yaml
filter: "evt.Line.Labels.type == 'unifi'"
pattern_syntax:
  ACTION: (D|R|A)
  ZONE: (LAN|WAN|LOCAL|VPN|DMZ)
statics:
  - meta: action
    expression: >-
      evt.Parsed.action == "D" ? "drop" :
      (evt.Parsed.action == "R" ? "reject" : "accept")
  - meta: log_type
    expression: >-
      evt.Meta.action not in ["accept", "unknown"] ?
      "iptables_drop" : "iptables_event"
```

**s00-raw/cef-logs.yaml** -- Parses CEF (Common Event Format) messages from the UniFi controller, including IPS alerts.

**s01-parse/unifi-cef.yaml** -- Enrichment parser for UniFi-specific CEF fields. Extracts 30+ metadata fields including IPS signatures, threat categories, risk levels, device details, and zone information.

**s01-parse/dropbear-logs.yaml** -- Parses SSH authentication failures from the UDM's dropbear daemon:

```yaml
filter: "evt.Parsed.program == 'dropbear'"
nodes:
  - grok:
      pattern: "Bad PAM password attempt for '%{DATA:user}' from %{IP:source_ip}:%{INT:port}"
  - grok:
      pattern: "Login attempt for nonexistent user from %{IP:source_ip}:%{INT:port}"
  - grok:
      pattern: "Exit before auth from <%{IP:source_ip}:%{INT:port}>:"
```

### Port scan scenario

Ships with a leaky-bucket scenario that detects aggressive TCP port scans: 3 or more distinct destination ports from the same source IP within 5 seconds triggers a ban.

```yaml
type: leaky
name: crowdsecurity/iptables-scan-multi_ports
description: "Detect aggressive portscans"
filter: "evt.Meta.log_type == 'iptables_drop' && evt.Meta.service == 'tcp'"
groupby: evt.Meta.source_ip
distinct: evt.Parsed.dst_port
capacity: 2
leakspeed: 5s
blackhole: 1m
labels:
  remediation: true
  classification:
    - attack.T1595.001
    - attack.T1046
  behavior: "tcp:scan"
```

### Supported hardware

Works on UDM, UDM SE, UDR, and UDM Pro -- any UniFi OS device with SSH access and iptables.

---

## 2. crowdsec-unifi-bouncer -- Enforcement

**Repository:** [github.com/wolffcatskyy/crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer)

Detection without enforcement is just a dashboard. The bouncer closes the loop.

### What it does

The bouncer runs directly on the UDM as a systemd service. It polls the CrowdSec LAPI every 10 seconds, retrieves active ban decisions, and enforces them at the firewall level using ipset and iptables. Banned IPs are blocked in both INPUT and FORWARD chains -- they cannot reach the router or any host behind it.

No Cloudflare. No reverse proxy. No external dependency. Bans happen at the network edge, on the device itself.

### The persistence problem (and how it's solved)

UniFi devices are hostile to customization. Firmware updates wipe iptables rules. The controller silently reprovisioning during normal operation can remove custom rules without warning. The `/data` directory is the only location guaranteed to survive across updates.

The bouncer solves this with three complementary persistence mechanisms:

1. **setup.sh** (ExecStartPre) -- Runs before every service start. Reloads kernel modules, recreates the ipset, restores iptables rules, and re-establishes systemd service links. Handles the "everything got wiped by a firmware update" case.

2. **ensure-rules.sh** (cron, every 5 minutes) -- Detects and silently re-adds iptables rules removed by the UniFi controller's reprovisioning process during normal operation. Handles the "controller randomly deleted my rules" case.

3. **`/data/crowdsec-bouncer/`** -- All files live in the single persistent directory that survives firmware updates, reboots, and controller reprovisioning.

### v2.0: Native Go binary, not Docker

The v1.x bouncer was a Python script running in Docker on the UDM. It hit MongoDB write storms that froze routers at 2,000+ blocked IPs. The v2.0 rewrite uses the official CrowdSec firewall bouncer binary (native Go), communicates directly with ipset via netfilter, and eliminates the UniFi controller API dependency entirely.

| | v1.x (Python/Docker) | v2.0 (Native Go) |
|---|---|---|
| Memory | 256+ MB | 15-22 MB |
| IP limit | ~2,000 (MongoDB bottleneck) | 100,000+ |
| Controller API | Required | Not needed |
| Persistence | Fragile | Triple-layer |

### Installation

```bash
# On the UDM (via SSH)
git clone https://github.com/wolffcatskyy/crowdsec-unifi-bouncer.git
cd crowdsec-unifi-bouncer
./install.sh

# On your CrowdSec host, generate a bouncer API key
cscli bouncers add unifi-bouncer

# Configure the bouncer on the UDM
vi /data/crowdsec-bouncer/crowdsec-firewall-bouncer.yaml
# Set api_url and api_key

# Start the service
systemctl enable crowdsec-firewall-bouncer
systemctl start crowdsec-firewall-bouncer
```

---

## 3. crowdsec-blocklist-import -- Intelligence

**Repository:** [github.com/wolffcatskyy/crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import)

The parser detects threats that reach your network. The blocklist importer blocks them before they ever connect.

### What it does

Aggregates 60,000+ IPs from 28 free public threat intelligence feeds and imports them directly into CrowdSec as ban decisions via the LAPI. Runs once and exits -- no daemon, no Docker socket required. About 600 lines of auditable bash.

### Threat feeds included

The tool pulls from curated, high-confidence sources:

| Category | Sources |
|----------|---------|
| Aggregated threat intel | IPsum (level 3+), Firehol Level 1-2 |
| Network-level blocklists | Spamhaus DROP/EDROP, DShield, CI Army |
| Malware infrastructure | Abuse.ch Feodo Tracker, SSL Blacklist, URLhaus |
| Brute force / abuse | Blocklist.de, GreenSnow, StopForumSpam |
| Scanner IPs | Shodan, Censys known scanners |
| Tor exit nodes | Tor Project, dan.me.uk |
| Compromised hosts | Emerging Threats |

### How it works

The script performs five sequential operations:

1. Fetches blocklists from 28 public sources
2. Consolidates and normalizes IP addresses
3. Filters out RFC1918 private/reserved ranges
4. Deduplicates against existing CrowdSec decisions (CAPI, console lists)
5. Bulk-imports new IPs via the CrowdSec LAPI

Decisions expire after 24 hours by default, so stale entries are automatically pruned. Running daily via cron keeps the list fresh.

### Installation

```bash
# One-line installer (auto-detects CrowdSec, creates LAPI credentials)
curl -sL https://raw.githubusercontent.com/wolffcatskyy/crowdsec-blocklist-import/main/install.sh | bash

# Or run via Docker Compose
docker compose up --abort-on-container-exit

# Schedule daily at 4 AM
0 4 * * * docker compose -f /path/to/docker-compose.yml up --abort-on-container-exit
```

### Three connection modes

| Mode | How it connects | When to use |
|------|----------------|-------------|
| **LAPI** (recommended) | Direct HTTP API to CrowdSec | Any setup; no Docker socket needed |
| **Docker** | `docker exec` into CrowdSec container | Legacy Docker setups |
| **Native** | `cscli` on the host directly | Bare-metal CrowdSec |

The installer auto-detects your setup and configures the appropriate mode.

---

## How the Three Projects Work Together

Each project is standalone and useful on its own. But together, they create something greater than the sum of their parts: a complete security feedback loop on commodity hardware.

```
                    ┌─────────────────────────────────────────┐
                    │           CROWDSEC ENGINE                │
                    │                                         │
  blocklist-import ─┤  60K+ preemptive bans (threat intel)    │
                    │         +                               │
  unifi-parser ────┤  Real-time detection (port scans,       │
                    │  SSH brute force, dropped packets)       │
                    │         =                               │
                    │  LAPI ban decisions                     │
                    │                                         │
                    └──────────────┬──────────────────────────┘
                                   │
                                   │ poll every 10s
                                   v
                    ┌─────────────────────────────────────────┐
                    │        UNIFI DREAM MACHINE              │
                    │                                         │
                    │  crowdsec-unifi-bouncer                 │
                    │    -> ipset + iptables                  │
                    │    -> INPUT + FORWARD chains            │
                    │    -> ipset/iptables DROP               │
                    │                                         │
                    │  Blocked at the edge.                   │
                    │  No Cloudflare. No proxy. No WAF.       │
                    └─────────────────────────────────────────┘
```

### The timeline of an attack

Here is what happens when a scanner hits your network with all three projects running:

1. **T+0s** -- Scanner sends SYN to port 22 on your WAN IP
2. **T+0s** -- UDM's existing DROP rule blocks the packet. The LOG rule (deployed by `crowdsec-unifi-parser`) fires first, writing a structured entry to kern.log
3. **T+0s** -- syslog-ng forwards the entry to your syslog server
4. **T+0s** -- CrowdSec's file acquisition reads the log line
5. **T+0s** -- `unifi-logs` parser extracts `source_ip=185.220.101.42`, `action=drop`, `dst_zone=LOCAL`
6. **T+2s** -- Scanner hits ports 443, 8080. Two more parsed events.
7. **T+3s** -- `iptables-scan-multi_ports` scenario fires: 3 distinct ports in under 5 seconds
8. **T+3s** -- CrowdSec issues a ban decision via LAPI
9. **T+13s** -- `crowdsec-unifi-bouncer` polls LAPI, picks up the new decision
10. **T+13s** -- IP added to ipset on the UDM. All future packets from this IP are silently dropped by netfilter rules across INPUT and FORWARD chains

Total time from first packet to network-wide ban: **~13 seconds**.

And if that scanner's IP was already in one of the 28 threat feeds? `crowdsec-blocklist-import` already banned it. The SYN packet at T+0 never even reached the firewall rules -- it was dropped by ipset before iptables processing.

---

## Deployment Summary

### Minimal setup (just detection)

```bash
# 1. Deploy LOG rules on UDM
pip3 install paramiko
python3 deploy-log-rules.py --host 192.168.1.1 --pass YOUR_PASSWORD

# 2. Configure syslog forwarding (UDM -> your server)
#    UniFi Controller: Settings -> System -> Advanced -> Remote Syslog

# 3. Set up rsyslog to write UniFi logs to a dedicated file
echo ':msg, contains, "UNIFI-" /var/log/unifi/unifi-fw.log' \
  | sudo tee /etc/rsyslog.d/10-unifi.conf
sudo systemctl restart rsyslog

# 4. Install CrowdSec parsers
git clone https://github.com/wolffcatskyy/crowdsec-unifi-parser.git
cd crowdsec-unifi-parser
sudo ./install.sh

# 5. Verify
sudo systemctl reload crowdsec
cscli metrics show parsers
```

### Full suite (detect + enforce + threat intel)

```bash
# Everything above, plus:

# 6. Install the bouncer on the UDM (via SSH)
ssh root@192.168.1.1
git clone https://github.com/wolffcatskyy/crowdsec-unifi-bouncer.git
cd crowdsec-unifi-bouncer && ./install.sh

# 7. Import threat feeds (on your CrowdSec host)
curl -sL https://raw.githubusercontent.com/wolffcatskyy/crowdsec-blocklist-import/main/install.sh | bash

# 8. Schedule daily blocklist refresh
echo '0 4 * * * docker compose -f /opt/crowdsec-blocklist-import/docker-compose.yml up --abort-on-container-exit' \
  | crontab -
```

---

## Technical Details at a Glance

| Component | Language | Size | Resource usage | License |
|-----------|----------|------|----------------|---------|
| [crowdsec-unifi-parser](https://github.com/wolffcatskyy/crowdsec-unifi-parser) | Python + YAML | ~1,200 lines | Runs once, exits | MIT |
| [crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer) | Go (official binary) + shell | ~15 MB binary | 15-22 MB RAM, <1% CPU | MIT |
| [crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import) | Bash | ~600 lines | Runs once, exits | MIT |

### Requirements

- **UniFi device**: UDM, UDM SE, UDR, or UDM Pro (any UniFi OS with SSH + iptables)
- **CrowdSec**: v1.4+ (tested with v1.6.x)
- **Syslog receiver**: rsyslog, syslog-ng, or similar
- **Python 3 + paramiko**: For the deploy script only (not a runtime dependency)

### What this is NOT

- This is not a replacement for UniFi's built-in firewall rules. The existing rules stay exactly as they are.
- This does not modify any firewall behavior. LOG rules are inserted _before_ DROP rules -- they observe and record, they do not change what gets dropped.
- This does not require Cloudflare, a reverse proxy, or any external service. Everything runs on your own hardware.
- This does not phone home. All three projects are fully auditable, open-source, and MIT-licensed.

---

## Why This Matters

UniFi sells more gateways than any other prosumer brand. CrowdSec is the fastest-growing open-source security engine. But until now, there was no bridge between them.

These three projects fill every gap:

| Gap | Project | What it provides |
|-----|---------|-----------------|
| No firewall visibility | **crowdsec-unifi-parser** | Structured log entries from every DROP rule |
| No threat detection | **CrowdSec + parser scenarios** | Port scan and SSH brute force detection |
| No preemptive blocking | **crowdsec-blocklist-import** | 60,000+ known-bad IPs blocked before they connect |
| No enforcement on UDM | **crowdsec-unifi-bouncer** | Ban decisions enforced via ipset/iptables |
| No feedback loop | **All three together** | Detect -> decide -> enforce -> detect |

The result: a UniFi Dream Machine that does not just block what you told it to block. It watches, learns, and responds -- in seconds, at the edge, with no external dependencies.

---

**All three projects are MIT-licensed and available on GitHub:**

- [crowdsec-unifi-parser](https://github.com/wolffcatskyy/crowdsec-unifi-parser) -- Visibility
- [crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer) -- Enforcement
- [crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import) -- Intelligence

Issues, PRs, and stars welcome.
