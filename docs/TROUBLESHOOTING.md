# Troubleshooting

## Common Issues

### deploy-log-rules.py fails to connect

**Symptom**: `SSH connection failed` or `Authentication failed`

**Fixes**:
1. Verify SSH access manually: `ssh root@<UDM_IP>`
2. UDM uses keyboard-interactive auth by default. The script handles this, but if it fails, check that SSH is enabled in UniFi settings
3. Make sure you're using the correct password (the UDM root password, not the UniFi controller password)
4. Check if the UDM SSH port is non-standard (use `--port`)

### No log entries appearing after deployment

**Symptom**: `deploy-log-rules.py` reports success but `/var/log/unifi/unifi-fw.log` is empty.

**Fixes**:
1. **Check on the UDM directly**: `ssh root@<UDM_IP> "tail -20 /var/log/messages | grep UNIFI-"`. If you see entries here, the LOG rules are working; the issue is syslog forwarding
2. **Check syslog forwarding**: In UniFi controller: Settings -> System -> Advanced -> Remote Syslog. Make sure the IP is correct
3. **Check rsyslog on receiver**: `sudo systemctl status rsyslog` and check for errors
4. **Test with netcat**: `nc -ul 514` on the receiver to see if any syslog arrives
5. **Wait for traffic**: LOG rules only fire when packets hit DROP rules. On a quiet network, it may take a few minutes

### CrowdSec shows 0% parse rate

**Symptom**: `cscli metrics` shows lines being read but none parsed.

**Fixes**:
1. **Check acquisition label**: The `acquis.d/unifi.yaml` must have `type: unifi` (not `type: syslog`). This label must match the parser filter `evt.Line.Labels.type == 'unifi'`
2. **Test parsing manually**:
   ```bash
   cscli explain --file /var/log/unifi/unifi-fw.log --type unifi
   ```
3. **Check log format**: The parser expects lines with `[UNIFI-*]` prefix. If your logs look different, you may need to adjust the grok pattern
4. **Verify parser is installed**:
   ```bash
   ls /etc/crowdsec/parsers/s00-raw/unifi-logs.yaml
   cscli parsers list
   ```

### "Chain does not exist" warnings

**Symptom**: `deploy-log-rules.py` warns that chains like `UBIOS_WAN_DMZ_USER` don't exist.

**This is normal**. Not all UDM configurations create all chains. For example:
- No DMZ network configured = no `UBIOS_WAN_DMZ_USER` chain
- No guest network = no `UBIOS_WAN_GUEST_USER` chain
- No VPN configured = no `UBIOS_WAN_VPN_USER` chain

The script skips missing chains safely.

### "No DROP rules found" in a chain

**Symptom**: A chain exists but has no DROP rules.

**Possible causes**:
1. The CrowdSec bouncer hasn't added any rules yet (normal on first install)
2. UniFi hasn't populated the chain (check your firewall rules in the controller)
3. The chain only has ACCEPT or RETURN rules

### LOG rules disappeared after reboot/firmware update

**Expected behavior**. UniFi regenerates iptables rules on:
- Firmware updates
- Reboots (rules persist, but may be regenerated)
- Controller reprovisioning

**Fix**: Re-run the deploy script:
```bash
python3 deploy-log-rules.py --host <UDM_IP> --pass <PASSWORD>
```

**Automation**: Add to cron or trigger after firmware updates:
```bash
# Run daily at 3 AM to ensure rules are present
0 3 * * * /path/to/deploy-log-rules.py --host 192.168.1.1 --pass "$UDM_PASS" >> /var/log/deploy-log-rules.log 2>&1
```

### Rate limiting is too aggressive / too lenient

**Default**: 10 events/minute with burst of 20.

During a heavy port scan (thousands of ports), you'll only see ~20 log entries in the first second, then 10/minute after that. This is intentional to prevent log flooding.

**To adjust**: Edit the constants in `deploy-log-rules.py`:
```python
RATE_LIMIT = "10/min"   # Change to "30/min" for more visibility
RATE_BURST = "20"       # Change to "50" for larger initial burst
```

Then re-run the script to re-deploy with new rate limits.

### CrowdSec Docker: parsers not loading

**Symptom**: Parsers are on the host but CrowdSec container doesn't see them.

**Fixes**:
1. Mount the parser files into the container (see README for docker-compose example)
2. Or copy files into the running container:
   ```bash
   docker cp parsers/s00-raw/unifi-logs.yaml crowdsec:/etc/crowdsec/parsers/s00-raw/
   docker restart crowdsec
   ```
3. Make sure the log file is also mounted into the container

### Port scan scenario not triggering

**Symptom**: Attackers scanning ports but no alerts generated.

**Fixes**:
1. **Check log_type**: The scenario filters on `evt.Meta.log_type == 'iptables_drop'`. Make sure the parser is setting this correctly
2. **Check service field**: The scenario also requires `evt.Meta.service == 'tcp'`. This is set by the iptables s01-parse stage from the PROTO field
3. **Threshold**: The default requires 3+ distinct destination ports in 5 seconds. A slow scan (1 port/minute) won't trigger it. Adjust `capacity` and `leakspeed` in the scenario
4. **Test with cscli**:
   ```bash
   cscli alerts list --scenario crowdsecurity/iptables-scan-multi_ports
   ```

## Diagnostic Commands

```bash
# Check what CrowdSec is acquiring
cscli metrics

# Test a specific log file against parsers
cscli explain --file /var/log/unifi/unifi-fw.log --type unifi

# List installed parsers
cscli parsers list

# List installed scenarios
cscli scenarios list

# Check for recent alerts
cscli alerts list

# Check decisions (active bans)
cscli decisions list

# View CrowdSec logs
journalctl -u crowdsec -f

# Check iptables rules on UDM (via SSH)
ssh root@<UDM_IP> "iptables -S UBIOS_WAN_LOCAL_USER | grep CROWDSEC_LOG"

# Count LOG rules on UDM
ssh root@<UDM_IP> "iptables -S | grep -c CROWDSEC_LOG"

# Watch firewall logs in real time
tail -f /var/log/unifi/unifi-fw.log
```

## Getting Help

1. Check the [CrowdSec documentation](https://docs.crowdsec.net/)
2. Open an issue on this repo
3. Join the [CrowdSec Discord](https://discord.gg/crowdsec)
