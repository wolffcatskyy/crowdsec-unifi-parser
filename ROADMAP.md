# Roadmap

## Current Status

**Version**: v1.0.0 (stable release)

The CrowdSec UniFi Parser is production-ready with:
- Full firewall log parsing (iptables DROP events)
- CEF event parsing (IPS alerts, controller events)
- 6 detection scenarios covering port scans, brute force, DDoS, and IPS alerts
- Automated iptables LOG rule deployment via SSH
- Complete documentation and troubleshooting guide

## v1.1.0 - Parser Improvements

Target: Q2 2025

### Parser Enhancements

- [ ] **IPv6 support**: Add parsing for IPv6 source/destination addresses in firewall logs
- [ ] **Inter-VLAN traffic logging**: Support `UBIOS_*_*_USER` chains beyond WAN-facing (LAN-to-LAN, LAN-to-GUEST, etc.)
- [ ] **NAT logging**: Parse DNAT/SNAT events from UniFi's NAT chains for visibility into port forwarding activity
- [ ] **Geo-enrichment**: Automatic GeoIP lookup for source IPs (requires CrowdSec GeoIP database)

### Scenario Improvements

- [ ] **Slow scan detection**: New scenario for low-and-slow port scans (1-2 ports/hour over 24h)
- [ ] **Protocol-specific scenarios**: Separate detection for UDP floods vs TCP SYN floods
- [ ] **Multi-device correlation**: Detect distributed scans hitting multiple internal hosts from the same source

### Deployment

- [ ] **Persistence script**: Optional `on-boot.d` script for UDM/UDR to auto-redeploy LOG rules after firmware updates
- [ ] **SSH key authentication**: Support for key-based SSH auth in addition to password auth

## v1.2.0 - Hub Submission

Target: Q3 2025

### CrowdSec Hub Integration

- [ ] **Hub submission**: Submit `unifi` collection to official CrowdSec Hub for `cscli collections install crowdsecurity/unifi`
- [ ] **Versioned parsers**: Align parser naming with Hub conventions
- [ ] **Test suite**: Add parser unit tests for Hub CI/CD pipeline

### Documentation

- [ ] **Video walkthrough**: Setup guide video covering UDM -> syslog -> CrowdSec -> bouncer
- [ ] **Helm chart**: Kubernetes deployment for CrowdSec with UniFi parsers pre-installed

## v2.0.0 - Extended UniFi Support

Target: 2026

### Platform Expansion

- [ ] **UniFi CloudKey Gen2+**: Parsing for CloudKey-specific logs
- [ ] **UniFi Network Application**: Direct API integration as alternative to syslog
- [ ] **UniFi Protect**: Camera motion detection and security events as CrowdSec signals

### Advanced Detection

- [ ] **Behavioral scenarios**: Detect reconnaissance patterns spanning multiple protocol types
- [ ] **Honeypot integration**: Trigger on access to designated honeypot IPs/ports
- [ ] **Threat intelligence correlation**: Cross-reference with CrowdSec CTI for known bad actors

## Contributing

Contributions welcome! Priority areas:

1. **Parser patterns**: If you encounter log formats that don't parse, open an issue with sanitized log samples
2. **Scenario tuning**: Real-world feedback on false positive rates and detection gaps
3. **Platform testing**: Validation on different UDM models (UDM, UDM Pro, UDM SE, UDR, UCG Ultra)

See the main README for contribution guidelines.

## Related Projects

| Project | Purpose |
|---------|---------|
| [crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import) | Import 120k+ IPs from 36 threat feeds |
| [crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer) | Push CrowdSec bans to UniFi firewall |
