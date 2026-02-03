# Architecture

## Overview

This project bridges the gap between UniFi's firewall and CrowdSec by creating structured, parseable log entries from iptables DROP events on the UDM.

## Data Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        UniFi Dream Machine                              │
│                                                                         │
│   iptables chains (UBIOS_WAN_*_USER):                                  │
│                                                                         │
│   Rule 1:  -m conntrack --ctstate INVALID                              │
│   Rule 2:  LOG --log-prefix "[UNIFI-WAN_LOCAL-D-INVALID]"  ← injected │
│   Rule 3:  -j DROP (INVALID state)                                     │
│   Rule 4:  ... other rules ...                                         │
│   Rule N:  LOG --log-prefix "[UNIFI-WAN_LOCAL-D-ALL]"      ← injected │
│   Rule N+1: -j DROP (catch-all)                                        │
│                                                                         │
│   LOG rules: rate-limited 10/min burst 20, comment CROWDSEC_LOG        │
│                                                                         │
│   kern.log / syslog-ng:                                                │
│   [UNIFI-WAN_LOCAL-D-INVALID] IN=eth4 SRC=x.x.x.x DST=y.y.y.y ...   │
│                                                                         │
└───────────────────────┬─────────────────────────────────────────────────┘
                        │ syslog (UDP 514)
                        v
┌─────────────────────────────────────────────────────────────────────────┐
│                       Syslog Receiver                                   │
│                                                                         │
│   rsyslog / syslog-ng receives logs from UDM                           │
│   Filters on "UNIFI-" prefix → writes to /var/log/unifi/unifi-fw.log  │
│                                                                         │
│   Example rsyslog config:                                              │
│   :msg, contains, "UNIFI-" /var/log/unifi/unifi-fw.log                │
│   & stop                                                                │
│                                                                         │
└───────────────────────┬─────────────────────────────────────────────────┘
                        │ file acquisition
                        v
┌─────────────────────────────────────────────────────────────────────────┐
│                         CrowdSec                                        │
│                                                                         │
│   Stage 0 (s00-raw): unifi-logs.yaml                                   │
│   ├─ Matches lines with label type == "unifi"                          │
│   ├─ Grok: extracts timestamp, hostname, zone, action, rule_id        │
│   ├─ Maps action codes: D→drop, R→reject, A→accept                    │
│   └─ Sets meta: log_type = "iptables_drop" or "iptables_event"        │
│                                                                         │
│   Stage 1 (s01-parse): handled by iptables collection                  │
│   ├─ Extracts: SRC, DST, SPT, DPT, PROTO from kernel log format       │
│   └─ Populates: meta.source_ip, meta.destination_port, etc.           │
│                                                                         │
│   Scenarios:                                                            │
│   ├─ iptables-scan-multi_ports: 3+ ports in 5s → ban                  │
│   ├─ ssh-bf: SSH brute force via dropbear parser                       │
│   └─ (standard iptables scenarios from crowdsec hub)                   │
│                                                                         │
│   Decisions:                                                            │
│   └─ Ban IPs that trigger scenarios → LAPI → bouncers                  │
│                                                                         │
└───────────────────────┬─────────────────────────────────────────────────┘
                        │ LAPI decisions
                        v
┌─────────────────────────────────────────────────────────────────────────┐
│                    crowdsec-unifi-bouncer                                │
│                    (separate project)                                    │
│                                                                         │
│   Polls CrowdSec LAPI for ban decisions                                │
│   Adds banned IPs to ipset on the UDM                                  │
│   iptables rules DROP packets from banned IPs                          │
│                                                                         │
│   Complete loop: detect → decide → enforce                              │
└─────────────────────────────────────────────────────────────────────────┘
```

## deploy-log-rules.py

### What It Does

1. **Connects** to the UDM via SSH (paramiko, keyboard-interactive auth)
2. **Cleans up** any existing `CROWDSEC_LOG` rules (idempotent, safe to re-run)
3. **Enumerates** DROP rules in all `UBIOS_WAN_*_USER` chains
4. **Inserts** a LOG rule immediately before each DROP rule
5. **Verifies** the rules were inserted correctly

### Rule Insertion Strategy

The script processes DROP rules from **bottom to top** within each chain. This is critical because inserting a rule shifts all subsequent rule indices. By starting at the bottom:

```
Before:                          After:
Rule 1: match-A → DROP          Rule 1: match-A → LOG (inserted)
Rule 2: match-B → DROP          Rule 2: match-A → DROP
                                 Rule 3: match-B → LOG (inserted)
                                 Rule 4: match-B → DROP
```

If we inserted top-to-bottom, the first insertion would shift the second DROP rule's index, and we'd insert the second LOG rule in the wrong place.

### LOG Rule Structure

Each injected rule has these components:

```
iptables -I CHAIN INDEX
  [original DROP rule match criteria]      # Same packets that would be dropped
  -m limit --limit 10/min --limit-burst 20 # Rate limiting
  -m comment --comment "CROWDSEC_LOG"      # Marker for idempotent cleanup
  -j LOG --log-prefix "[UNIFI-ZONE-D-TYPE] " --log-level 4
```

- **Match criteria**: Copied from the DROP rule so the LOG fires on the same packets
- **Rate limit**: Prevents log flooding during scans (10 entries/min, burst of 20)
- **Comment marker**: Allows cleanup phase to find and remove old rules
- **Log prefix**: Structured tag for easy parsing: `[UNIFI-{zone}-{action}-{type}]`

### Log Prefix Format

```
[UNIFI-WAN_LOCAL-D-INVALID]
  │      │          │  │
  │      │          │  └── Rule type: INVALID (conntrack) or ALL (catch-all)
  │      │          └───── Action: D (drop), R (reject), A (accept)
  │      └──────────────── Zone: WAN_LOCAL, WAN_LAN, WAN_IN, etc.
  └─────────────────────── Fixed prefix for grep/rsyslog filtering
```

## Parser Pipeline

### Stage 0: unifi-logs.yaml (Raw Parser)

Triggered when `evt.Line.Labels.type == 'unifi'`.

Uses a custom grok pattern that handles both:
- Standard syslog format with UNIFI firewall prefix
- ISO 8601 timestamp format
- Hostname with optional MAC address and firmware version

Extracts: `timestamp`, `hostname`, `dst_zone`, `action`, `rule_id`, `program`, `message`

Maps action codes to human-readable values:
- `D` -> `drop`
- `R` -> `reject`
- `A` -> `accept`

Sets `meta.log_type` to `iptables_drop` (for drop/reject) or `iptables_event` (for accept/unknown), which downstream scenarios filter on.

### Stage 0: cef-logs.yaml (CEF Raw Parser)

Handles CEF (Common Event Format) logs from the UniFi controller.

Extracts the CEF header fields: vendor, product, version, signature ID, event name, severity.

### Stage 1: unifi-cef.yaml (CEF Enrichment)

Triggered when `cef_device_vendor == 'Ubiquiti'` and `cef_device_product == 'UniFi Network'`.

Parses key-value pairs from the CEF extension and extracts 30+ fields including:
- Network: source/dest IP, port, protocol
- Security: IPS signature, category, risk level
- Device: name, model, firmware, interface
- Administrative: admin user, access method, policy

### Stage 1: dropbear-logs.yaml (SSH Parser)

Handles SSH authentication failures from UDM's dropbear SSH daemon:
- Bad password attempts
- Non-existent user login attempts
- Pre-auth disconnections

## Collection: unifi.yaml

Bundles everything together:
- **Parsers**: unifi-logs, cef-logs, unifi-cef, dropbear-logs
- **Scenarios**: ssh-bf (brute force)
- **Collections**: iptables (includes iptables-specific parsers and scenarios)

This means installing the collection also pulls in the standard CrowdSec iptables support, which provides the Stage 1 parsing for kernel iptables log format (SRC, DST, SPT, DPT, PROTO extraction).
