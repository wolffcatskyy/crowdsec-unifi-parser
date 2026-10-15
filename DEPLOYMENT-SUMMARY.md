# UDR Deployment Summary

## Date
2026-02-03

## Objective
Deploy iptables LOG rules on UniFi Dream Router (UDR) at <UDR_WAN_IP> / <UDR_LAN_IP> for CrowdSec visibility.

## Status
**BLOCKED** - Awaiting SSH access resolution

## What Was Done

### 1. Environment Setup
- Installed paramiko on macpro: `python3 -m pip install --user paramiko`
- Verified deploy script at `/private/tmp/crowdsec-unifi-parser/deploy-log-rules.py`
- Script is working (previously deployed successfully on UDM SE at <UDM_SE_IP>)

### 2. Connection Testing
Tested multiple access paths to UDR:

| Method | Target | Result |
|--------|--------|--------|
| SSH via WAN IP | <UDR_WAN_IP>:22 | TIMEOUT (port firewalled) |
| HTTPS via WAN IP | <UDR_WAN_IP>:443 | SUCCESS (web UI accessible) |
| Ping via LAN IP | <UDR_LAN_IP> | FAILED (no route from macpro) |
| SSH via LAN IP | <UDR_LAN_IP>:22 | NOT TESTED (no route) |

### 3. Network Analysis
**macpro topology**:
- Local subnet: <NETWORK_ADDRESS>/22
- Can reach: <NETWORK_ADDRESS>/24 (NAS network)
- Cannot reach: <NETWORK_ADDRESS>/24 (UDR network)
- No WireGuard VPN configured
- Has Tailscale (utun4) but doesn't provide route to <NETWORK_ADDRESS>/24

**Root cause**: UDR is on isolated network segment with no routing configured.

### 4. Documentation Created

#### Files Created
1. **UDR-DEPLOY-STATUS.md** - Detailed status, options, and troubleshooting
2. **UDR-QUICK-DEPLOY.sh** - Automated deployment script for when access is available
3. **DEPLOYMENT-SUMMARY.md** - This file

## Blocker Analysis

### Why SSH Access Failed
UniFi devices follow security best practices:
- SSH is disabled on WAN interface by default
- Only HTTPS (443) and essential services exposed on WAN
- SSH access intended via LAN or UniFi management interface
- The WAN IP (<UDR_WAN_IP>) serves the web UI but blocks SSH

### Network Isolation
The UDR LAN IP (<UDR_LAN_IP>) is not reachable from:
- macpro (<NETWORK_ADDRESS>/22 network)
- NAS harlow (<NAS_IP>)
- No VPN route configured

## Solutions (Ordered by Recommendation)

### Option 1: Enable WAN SSH Temporarily (RECOMMENDED)
**Steps**:
1. Access https://<UDR_WAN_IP> (UniFi web UI)
2. Navigate to: Settings > System > Advanced
3. Enable SSH access
4. Look for "SSH on WAN" option and enable if available
5. Run deployment: `./UDR-QUICK-DEPLOY.sh` (sets UDR_HOST=<UDR_WAN_IP>)
6. Disable WAN SSH after completion

**Pros**: Quick, uses automated script, verifies deployment
**Cons**: Temporarily exposes SSH on WAN (mitigated by disabling afterward)

### Option 2: Access via LAN
**Requirements**:
- Physical or VPN access to <NETWORK_ADDRESS>/24 network
- Or configure routing between <NETWORK_ADDRESS>/22 and <NETWORK_ADDRESS>/24

**Steps**:
1. Connect to UDR network (direct connection or routing/VPN)
2. Run: `UDR_HOST=<UDR_LAN_IP> ./UDR-QUICK-DEPLOY.sh`

**Pros**: More secure (no WAN exposure)
**Cons**: Requires network topology changes or physical access

### Option 3: Manual Console Deployment
**Steps**:
1. Access https://<UDR_WAN_IP>
2. Navigate to: System > Console (or SSH via UniFi application)
3. Run commands manually (see UDR-DEPLOY-STATUS.md "Manual Commands" section)

**Pros**: Works without SSH daemon access
**Cons**: Error-prone, no automated verification, tedious

### Option 4: Configure VPN Route
If WireGuard VPN on hplaptop can be configured to route <NETWORK_ADDRESS>/24:
1. Connect to VPN
2. Deploy via LAN IP (<UDR_LAN_IP>)

**Pros**: Secure remote access
**Cons**: Requires VPN configuration changes

## Deployment Command (Once Access Available)

### Quick Method
```bash
cd /private/tmp/crowdsec-unifi-parser

# For WAN access (if SSH enabled on WAN)
UDR_HOST=<UDR_WAN_IP> UDR_USER=root ./UDR-QUICK-DEPLOY.sh

# For LAN access
UDR_HOST=<UDR_LAN_IP> UDR_USER=root ./UDR-QUICK-DEPLOY.sh
```

### Manual Method
```bash
# Dry run first
python3 deploy-log-rules.py \
  --host <IP> \
  --user root \
  --pass '<UDR_SSH_PASSWORD>' \
  --dry-run

# Actual deployment
python3 deploy-log-rules.py \
  --host <IP> \
  --user root \
  --pass '<UDR_SSH_PASSWORD>'
```

## Post-Deployment Checklist

Once SSH access is established and rules are deployed:

- [ ] Verify iptables rules deployed (script does this automatically)
- [ ] Configure syslog forwarding on UDR
  - Remote syslog server: <NAS_IP>
  - Port: 514
  - Protocol: UDP
- [ ] Test syslog forwarding: `ssh root@<UDR_IP> 'logger -t UNIFI-TEST "Test from UDR"'`
- [ ] Verify logs arrive on NAS: `ssh nas 'tail -f /var/log/messages | grep UNIFI'`
- [ ] Check CrowdSec parser: `ssh nas 'docker exec crowdsec cscli parsers test crowdsecurity/unifi-logs'`
- [ ] Monitor for actual DROP events
- [ ] Document completion in UDR-DEPLOY-STATUS.md
- [ ] Schedule re-deployment after firmware updates

## Expected Results

When deployment succeeds:
```
--- Phase 2: Deploy LOG rules before DROP rules ---
Processing chain: UBIOS_WAN_LOCAL_USER (WAN_LOCAL)
  Found 2 DROP rule(s) in UBIOS_WAN_LOCAL_USER
  Inserting: LOG before DROP #5 (ALL) in UBIOS_WAN_LOCAL_USER
  Inserting: LOG before DROP #2 (INVALID) in UBIOS_WAN_LOCAL_USER
Processing chain: UBIOS_WAN_LAN_USER (WAN_LAN)
  Found 2 DROP rule(s) in UBIOS_WAN_LAN_USER
  [... etc ...]

--- Phase 3: Verification ---
  Verified: 2 LOG rule(s) in WAN_LOCAL
  Verified: 2 LOG rule(s) in WAN_LAN
  [... etc ...]

SUCCESS: 14 LOG rules deployed across 7 chain(s)
```

## Reference Deployment (UDM SE)
The same script was successfully deployed on UDM SE (<UDM_SE_IP>) and is currently working. This proves:
- Script works correctly
- Paramiko authentication works
- CrowdSec parser is receiving and parsing logs
- The UDR deployment will follow the same successful pattern

## Next Action Required
**User Decision**: Choose access method (Option 1 recommended) and proceed with deployment.

## Files for Deployment
- Main script: `/private/tmp/crowdsec-unifi-parser/deploy-log-rules.py`
- Quick deploy: `/private/tmp/crowdsec-unifi-parser/UDR-QUICK-DEPLOY.sh`
- Status doc: `/private/tmp/crowdsec-unifi-parser/UDR-DEPLOY-STATUS.md`
- This summary: `/private/tmp/crowdsec-unifi-parser/DEPLOYMENT-SUMMARY.md`
