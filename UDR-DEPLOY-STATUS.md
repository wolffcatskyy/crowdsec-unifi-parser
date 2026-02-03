# UDR Deployment Status

## Date/Time
2026-02-03 13:30 PST

## Attempted Deployment
**Target Device**: UniFi Dream Router (UDR)
- WAN IP: 47.202.19.61
- LAN IP: 192.168.21.1 (not routable from NAS)
- SSH User: claude-code
- SSH Port: 22 (standard)

## Result
**FAILED** - SSH port not accessible on WAN interface

## Details

### Issue
The UDR's WAN IP (47.202.19.61) is reachable via HTTPS (curl returns UniFi OS web page), but SSH port 22 is **blocked/firewalled** on the WAN interface.

Connection attempts:
```
$ curl --connect-timeout 5 -v telnet://47.202.19.61:22
* Failed to connect to 47.202.19.61 port 22 after 5005 ms: Timeout was reached
```

### Root Cause
UniFi devices typically **do not expose SSH on the WAN interface by default** for security reasons. SSH is typically only available on:
- LAN interface
- Management VLAN
- Via UniFi Network Application (remote access)

### Options to Resolve

#### Option 1: Enable WAN SSH Access (Quick but less secure)
1. Log into UDR via web UI at https://47.202.19.61
2. Navigate to Settings > System > Device Authentication
3. Enable "SSH" and potentially "Advanced" > "Enable SSH on WAN"
4. Note: This is generally not recommended for security reasons

#### Option 2: Access via LAN (Recommended)
Since the UDR LAN IP (192.168.21.1) is not routable from the NAS, you would need to:
1. Temporarily connect from a device on the 192.168.21.0/24 network
2. Run the deploy script from that device:
   ```bash
   python3 deploy-log-rules.py --host 192.168.21.1 --user root --pass '!#o#It0S!#o#It0S'
   ```
3. Alternative: Run from macpro if it has route to 192.168.21.0/24

#### Option 3: VPN/Tunnel Access
If WireGuard or another VPN provides access to the 192.168.21.0/24 network:
1. Connect to VPN
2. Access UDR via LAN IP
3. Run deployment script

#### Option 4: UniFi Network Application SSH
If the UDR is managed by a UniFi Network Application:
1. Use the application's SSH feature to access the device
2. Manually run the iptables commands from the deploy script

## Script Readiness
The deploy script (`deploy-log-rules.py`) is ready and tested:
- Paramiko installed successfully
- Script syntax validated
- Dry-run mode available
- Successfully deployed on UDM SE (192.168.18.1)

## Next Steps

### Immediate Action Required
**Determine access method** and choose one of the options above.

### After SSH Access is Established
1. Run dry-run first:
   ```bash
   python3 /private/tmp/crowdsec-unifi-parser/deploy-log-rules.py \
     --host <IP> --user <USER> --pass '<PASSWORD>' --dry-run
   ```

2. If dry-run looks good, deploy for real:
   ```bash
   python3 /private/tmp/crowdsec-unifi-parser/deploy-log-rules.py \
     --host <IP> --user <USER> --pass '<PASSWORD>'
   ```

3. Verify rules were inserted (script does this automatically)

### Post-Deployment Tasks
After successful deployment:
1. Configure syslog forwarding on UDR to send logs to NAS (192.168.18.10:514)
2. Test that CrowdSec parser is receiving and parsing UDR logs
3. Monitor `/var/log/messages` on NAS for [UNIFI-*] entries from UDR
4. Update this status document with success details

## Network Topology Analysis

### Current Situation
- **macpro** (192.168.4.32): Can reach 192.168.18.0/24 but NOT 192.168.21.0/24
- **NAS harlow** (192.168.18.10): Can reach 192.168.18.0/24 but NOT 192.168.21.0/24
- **UDR** (192.168.21.1): Separate network segment, no routing configured
- **UDR WAN** (47.202.19.61): SSH port 22 is firewalled (connection timeout)

### Tested Paths
1. macpro -> 192.168.21.1: No route (100% packet loss)
2. macpro -> 47.202.19.61:22: Connection timeout (firewall/disabled)
3. macpro -> 47.202.19.61:443: SUCCESS (UniFi web UI accessible)

## Technical Notes

### Why WAN SSH is Blocked
UniFi Best Practices:
- SSH on WAN is disabled by default for security
- Only essential services (HTTPS, VPN) exposed on WAN
- Management access intended via LAN or UniFi cloud

### Alternative: SSH via Different Port
Some users configure SSH on non-standard WAN port (2222, 8022, etc.)
- Would need to check UDR configuration
- Test with: `--port <PORT_NUMBER>`

### Manual Deployment Option
If SSH access cannot be established remotely, the iptables rules can be deployed manually:
1. Access UDR console via UniFi web UI (https://47.202.19.61) -> System -> Console
2. Copy commands from deploy script and run manually
3. See "Manual Commands" section below

## Files
- Deploy script: `/private/tmp/crowdsec-unifi-parser/deploy-log-rules.py`
- Status document: `/private/tmp/crowdsec-unifi-parser/UDR-DEPLOY-STATUS.md`
- UDM SE deployment: Successfully completed (reference implementation)

## Manual Commands (If SSH Automation Fails)

If you need to deploy the rules manually via the UniFi console, here's the concept:

### Step 1: Cleanup (Remove old CROWDSEC_LOG rules)
```bash
# For each chain, repeatedly remove CROWDSEC_LOG rules until none remain
for chain in UBIOS_WAN_LOCAL_USER UBIOS_WAN_LAN_USER UBIOS_WAN_IN_USER \
             UBIOS_WAN_DMZ_USER UBIOS_WAN_GUEST_USER UBIOS_WAN_VPN_USER \
             UBIOS_WAN_WAN_USER; do
  while iptables -L $chain --line-numbers -n 2>/dev/null | grep CROWDSEC_LOG; do
    rule_num=$(iptables -L $chain --line-numbers -n | grep CROWDSEC_LOG | head -1 | awk '{print $1}')
    iptables -D $chain $rule_num
  done
done
```

### Step 2: List DROP rules
```bash
# Example for one chain (repeat for all chains)
iptables -S UBIOS_WAN_LOCAL_USER | grep -n "DROP"
```

### Step 3: Insert LOG rules before each DROP
For each DROP rule found, insert a LOG rule at that index. Example:
```bash
# If DROP rule is at index 5, insert LOG at index 5 (pushing DROP to 6)
iptables -I UBIOS_WAN_LOCAL_USER 5 \
  -m conntrack --ctstate INVALID \
  -m limit --limit 10/min --limit-burst 20 \
  -m comment --comment "CROWDSEC_LOG" \
  -j LOG --log-prefix "[UNIFI-WAN_LOCAL-D-INVALID] " --log-level 4
```

NOTE: The automated script handles all of this complexity. Manual deployment is error-prone and not recommended unless absolutely necessary.

## Recommended Solution

**BEST PATH FORWARD**: Enable SSH on WAN interface temporarily
1. Access UniFi web UI: https://47.202.19.61
2. Login with admin credentials
3. Settings > System > Advanced > Enable SSH
4. Check if "SSH on WAN" option exists and enable it temporarily
5. Run the automated deploy script
6. Disable WAN SSH after deployment completes
7. Rules will persist until next firmware update or iptables flush

This is the quickest path to deployment while maintaining the automation and verification that the Python script provides.

## Contact
If access method is unclear or assistance needed:
1. Verify UDR network topology (routing from macpro to 192.168.21.1)
2. Check if VPN provides 192.168.21.0/24 access
3. Consider temporary WAN SSH enablement if security requirements allow
4. As last resort, use manual console commands (see above)
