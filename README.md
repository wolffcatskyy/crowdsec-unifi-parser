# CrowdSec UniFi Parser

Get clean, CrowdSec-parseable firewall logs from UniFi Dream Machines -- no more syslog noise.

Deploys targeted iptables LOG rules on your UDM/UDR and provides custom CrowdSec parsers that extract source IP, destination IP, port, protocol, zone, and action from every dropped packet.

> **New to CrowdSec?** [CrowdSec](https://crowdsec.net) is a free, open-source security engine that detects and blocks malicious IPs. It works like fail2ban but with crowd-sourced threat intelligence and a modern bouncer ecosystem. Install it, connect bouncers to your firewalls/proxies, and threats get blocked network-wide.

## What You Need

**Yes, this requires a separate machine running CrowdSec.** CrowdSec doesn't run on the UDM itself. Here's what goes where:

| What | Where it runs | What it does |
|------|--------------|-------------|
| `deploy-log-rules.py` | Any machine with Python 3 (your laptop, a server, etc.) | One-time SSH into UDM to insert LOG rules. Run once, then again after firmware updates. |
| Syslog receiver (rsyslog) | Your CrowdSec host or any Linux box | Receives syslog from UDM, writes firewall entries to a file |
| CrowdSec + these parsers | Same machine as syslog receiver | Reads the log file, detects threats, issues ban decisions |
| UDM / UDR | Your UniFi device | Sends syslog. That's it. No software installed, no extra load. |

A typical setup: UDM sends syslog to a Raspberry Pi / NAS / VM running CrowdSec. The deploy script runs from your laptop.

## The Problem

If you've tried to feed UniFi syslog into CrowdSec, you've hit a wall:

- **99% noise**: UniFi's default syslog output is flooded with kernel link-state changes, camera events, controller chatter, and firmware messages
- **0% parse rate**: CrowdSec has no built-in parser for UniFi firewall logs. Point it at raw UniFi syslog and you get `0 parsed / 47,231 unparsed`
- **No official support**: There's no CrowdSec collection for UniFi. The [CrowdSec Hub](https://hub.crowdsec.net/) has parsers for pfsense, OPNsense, and iptables -- but nothing for UniFi
- **Firewall events are invisible**: UniFi drops packets silently. There's no log entry when a packet hits a DROP rule unless you add one yourself

## The Solution

This project takes a different approach: instead of trying to parse UniFi's noisy default syslog, we **inject clean, structured log entries** directly into the kernel log by deploying iptables LOG rules on the UDM.

```
UDM iptables LOG rules          CrowdSec parsers
        |                              |
        v                              v
  [UNIFI-WAN_LOCAL-D-INVALID]    Extract: source_ip, dst_ip,
  IN=eth4 SRC=45.33.32.156      port, protocol, zone, action
  DST=192.168.1.1 PROTO=TCP
  DPT=22                         -> Port scan detection
                                  -> Brute force detection
                                  -> CrowdSec decisions
```

### How It Works

```
+-------------------+     syslog-ng      +------------------+     file/syslog     +------------------+
|    UDM / UDR      | -----------------> |  Syslog Server   | -----------------> |    CrowdSec      |
|                   |     (UDP 514)      |  (rsyslog, etc)  |     acquisition    |                  |
|  iptables LOG     |                    |  unifi-fw.log    |                    |  unifi-logs      |
|  rules deployed   |                    |                  |                    |  parser          |
|  before every     |                    |                  |                    |  -> scenarios    |
|  DROP rule        |                    |                  |                    |  -> decisions    |
+-------------------+                    +------------------+                    +------------------+
         |                                                                               |
         |  deploy-log-rules.py                                              crowdsec-unifi-bouncer
         |  (SSH + paramiko)                                                 (push bans back to UDM)
         |                                                                               |
         +<---------- Complete feedback loop: detect -> ban -> enforce ---------<---------+
```

## Features

- **Works on UDM, UDM SE, UDR, UDM Pro** -- any UniFi OS device with SSH and iptables
- **Survives firmware updates** -- just re-run the deploy script after upgrading
- **Rate limited** (10/min burst 20) to prevent log flooding during scans
- **Idempotent deployment** -- safe to run repeatedly; cleans up old rules first
- **Dry-run mode** -- preview changes without touching iptables
- **Full CrowdSec integration** -- parsers + scenarios + collection bundle
- **Clean tagged log entries** like `[UNIFI-WAN_LOCAL-D-INVALID]` that are trivial to parse
- **Two log pipelines**: syslog-based firewall logs AND CEF-format controller events
- **Port scan detection** out of the box (3+ ports in 5 seconds = ban)
- **SSH brute force detection** via dropbear parser (UDM's SSH daemon)
- **Pairs with [crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer)** for a complete detect-and-block loop

## Quick Start

### 1. Deploy LOG rules on your UDM

```bash
# Install paramiko
pip3 install paramiko

# Deploy LOG rules (SSH into UDM and insert iptables rules)
python3 deploy-log-rules.py --host 192.168.1.1 --user root --pass YOUR_PASSWORD

# Or use environment variables
export UDM_PASS=YOUR_PASSWORD
python3 deploy-log-rules.py --host 192.168.1.1

# Preview changes without applying
python3 deploy-log-rules.py --host 192.168.1.1 --pass YOUR_PASSWORD --dry-run
```

### 2. Set up syslog forwarding

Configure your UDM to forward syslog to a remote server. In the UniFi controller:

**Settings -> System -> Advanced -> Remote Syslog Server**

Set the IP to your syslog receiver (e.g., your CrowdSec host or a dedicated syslog server).

On the receiving end, configure rsyslog to write UniFi logs to a dedicated file:

```bash
# /etc/rsyslog.d/10-unifi.conf
:msg, contains, "UNIFI-" /var/log/unifi/unifi-fw.log
& stop
```

### 3. Install CrowdSec parsers

```bash
# Clone this repo
git clone https://github.com/wolffcatskyy/crowdsec-unifi-parser.git
cd crowdsec-unifi-parser

# Run the installer
sudo ./install.sh

# Or install manually
sudo cp parsers/s00-raw/unifi-logs.yaml /etc/crowdsec/parsers/s00-raw/
sudo cp parsers/s00-raw/cef-logs.yaml /etc/crowdsec/parsers/s00-raw/
sudo cp parsers/s01-parse/unifi-cef.yaml /etc/crowdsec/parsers/s01-parse/
sudo cp parsers/s01-parse/dropbear-logs.yaml /etc/crowdsec/parsers/s01-parse/
sudo cp scenarios/iptables-scan-multi_ports.yaml /etc/crowdsec/scenarios/
sudo cp collections/unifi.yaml /etc/crowdsec/collections/
```

### 4. Configure acquisition

```bash
# Copy the example acquisition config
sudo cp acquis.d/unifi.yaml /etc/crowdsec/acquis.d/

# Edit the log path to match your setup
sudo nano /etc/crowdsec/acquis.d/unifi.yaml
```

### 5. Reload CrowdSec

```bash
sudo systemctl reload crowdsec

# Verify parsers are loaded
cscli metrics

# You should see lines being parsed under "unifi-logs"
```

## What Gets Parsed

### Firewall Log Format

The deploy script creates log entries like this:

```
Feb  1 14:23:45 UDM kernel: [UNIFI-WAN_LOCAL-D-INVALID] IN=eth4 OUT= MAC=xx:xx:xx SRC=185.220.101.42 DST=192.168.1.1 LEN=40 TOS=0x00 TTL=243 ID=54321 PROTO=TCP SPT=54321 DPT=22 WINDOW=1024 SYN
```

The parser extracts:

| Field | Example | Description |
|-------|---------|-------------|
| `source_ip` | `185.220.101.42` | Attacker IP |
| `dst_zone` | `LOCAL` | Destination zone (LOCAL, LAN, WAN, VPN, DMZ) |
| `action` | `drop` | Firewall action (drop, reject, accept) |
| `log_type` | `iptables_drop` | Used by scenarios for filtering |
| `hostname` | `UDM` | Device hostname |
| `protocol` | `TCP` | IP protocol |
| Ports, MAC, etc. | ... | Full iptables log fields |

### CEF Event Format

UniFi also emits CEF (Common Event Format) logs for controller events:

```
CEF:0|Ubiquiti|UniFi Network|8.6.9|3004|IPS Alert|7|src=45.33.32.156 dst=192.168.1.100 ...
```

The CEF parser extracts IPS alerts, threat events, admin actions, and more.

### Chains Covered

| Chain | Zone | What It Catches |
|-------|------|-----------------|
| `UBIOS_WAN_LOCAL_USER` | WAN -> Router | SSH scans, management probes |
| `UBIOS_WAN_LAN_USER` | WAN -> LAN | Inbound attacks to LAN hosts |
| `UBIOS_WAN_IN_USER` | WAN -> Internal | Port forwards, NAT traversal attempts |
| `UBIOS_WAN_DMZ_USER` | WAN -> DMZ | DMZ-targeted attacks |
| `UBIOS_WAN_GUEST_USER` | WAN -> Guest | Guest network probes |
| `UBIOS_WAN_VPN_USER` | WAN -> VPN | VPN endpoint attacks |
| `UBIOS_WAN_WAN_USER` | WAN -> WAN | Transit traffic drops |

## Scenarios Included

### Port Scan Detection (`iptables-scan-multi_ports`)

Detects aggressive TCP port scans: 3+ distinct destination ports from the same source IP within 5 seconds triggers a ban.

- **Type**: Leaky bucket
- **Capacity**: 2 (triggers on 3rd distinct port)
- **Leak speed**: 5 seconds
- **Blackhole**: 1 minute (suppress duplicate alerts)
- **Labels**: `remediation: true` (CrowdSec will issue a ban decision)
- **MITRE ATT&CK**: T1595.001, T1018, T1046

### SSH Brute Force (via `crowdsecurity/ssh-bf`)

The collection includes the standard CrowdSec SSH brute force scenario, which works with the dropbear parser for UDM SSH authentication failures.

## Docker CrowdSec Setup

If you run CrowdSec in Docker, mount the log file and config:

```yaml
# docker-compose.yaml
services:
  crowdsec:
    image: crowdsecurity/crowdsec
    volumes:
      # Mount UniFi firewall logs
      - /var/log/unifi:/var/log/unifi:ro
      # Mount custom parsers (or use install.sh inside container)
      - ./parsers/s00-raw/unifi-logs.yaml:/etc/crowdsec/parsers/s00-raw/unifi-logs.yaml:ro
      - ./parsers/s00-raw/cef-logs.yaml:/etc/crowdsec/parsers/s00-raw/cef-logs.yaml:ro
      - ./parsers/s01-parse/unifi-cef.yaml:/etc/crowdsec/parsers/s01-parse/unifi-cef.yaml:ro
      - ./parsers/s01-parse/dropbear-logs.yaml:/etc/crowdsec/parsers/s01-parse/dropbear-logs.yaml:ro
      - ./scenarios/iptables-scan-multi_ports.yaml:/etc/crowdsec/scenarios/iptables-scan-multi_ports.yaml:ro
      - ./collections/unifi.yaml:/etc/crowdsec/collections/unifi.yaml:ro
      - ./acquis.d/unifi.yaml:/etc/crowdsec/acquis.d/unifi.yaml:ro
```

## File Structure

```
crowdsec-unifi-parser/
├── README.md                              # This file
├── LICENSE                                # MIT
├── deploy-log-rules.py                    # iptables LOG rule deployer (runs on UDM via SSH)
├── install.sh                             # One-command installer
├── parsers/
│   ├── s00-raw/
│   │   ├── unifi-logs.yaml                # Raw UniFi syslog parser
│   │   └── cef-logs.yaml                  # CEF (Common Event Format) parser
│   └── s01-parse/
│       ├── unifi-cef.yaml                 # UniFi CEF event enrichment
│       └── dropbear-logs.yaml             # UDM SSH auth failure parser
├── scenarios/
│   └── iptables-scan-multi_ports.yaml     # TCP port scan detection
├── collections/
│   └── unifi.yaml                         # Collection bundle
├── acquis.d/
│   └── unifi.yaml                         # Example acquisition config
└── docs/
    ├── ARCHITECTURE.md                    # Detailed architecture walkthrough
    └── TROUBLESHOOTING.md                 # Common issues and fixes
```

## Verify It's Working

After installation, check CrowdSec metrics:

```bash
# Check acquisition (are logs being read?)
cscli metrics | grep unifi

# Check parser success rate
cscli metrics show parsers

# Check for alerts
cscli alerts list

# Watch logs in real time
tail -f /var/log/unifi/unifi-fw.log

# Test the full pipeline
cscli explain --file /var/log/unifi/unifi-fw.log --type unifi
```

You should see output like:
```
line: Feb  1 14:23:45 UDM kernel: [UNIFI-WAN_LOCAL-D-INVALID] IN=eth4 ...
        ├ s00-raw/unifi-logs        ✅ success
        └ s01-parse/iptables-logs   ✅ success
                ├ meta.source_ip     185.220.101.42
                ├ meta.log_type      iptables_drop
                └ meta.action        drop
```

## Re-running After Firmware Updates

UniFi firmware updates regenerate all iptables rules, which removes the LOG rules. After a firmware update:

```bash
python3 deploy-log-rules.py --host 192.168.1.1 --pass YOUR_PASSWORD
```

Consider adding this to a cron job or running it as part of your firmware update procedure.

## Complete UniFi + CrowdSec Suite

This parser is part of a three-project suite that gives UniFi full CrowdSec integration:

| Project | Role | What it does |
|---------|------|-------------|
| **This repo** | Visibility | Deploys iptables LOG rules on your UDM/UDR so CrowdSec can detect port scans, brute force, and other threats from your firewall logs |
| **[crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import)** | Intelligence | Imports 60,000+ IPs from 28 public threat feeds into CrowdSec — preemptive blocking before attackers even connect |
| **[crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer)** | Enforcement | Pushes CrowdSec ban decisions to your UniFi firewall via ipset/iptables — 100k+ IPs, 15MB RAM, survives firmware updates |

Together: this **parser** detects threats, **blocklist-import** feeds threat intel, and the **bouncer** enforces bans. A complete detect → decide → enforce feedback loop on UniFi hardware for free.

## Requirements

- **UniFi device**: UDM, UDM SE, UDR, UDM Pro (any UniFi OS with SSH + iptables)
- **CrowdSec**: v1.4+ (tested with v1.6.x)
- **Python 3**: For the deploy script
- **paramiko**: `pip3 install paramiko`
- **Syslog forwarding**: UDM -> remote syslog server -> CrowdSec acquisition

## License

MIT
