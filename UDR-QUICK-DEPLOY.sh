#!/bin/bash
# UDR Quick Deploy Script
# Run this once SSH access to UDR is available

set -e

echo "=============================================="
echo "UDR CrowdSec LOG Rules Deployment"
echo "=============================================="
echo ""

# Configuration
UDR_HOST="${UDR_HOST:-192.168.21.1}"
UDR_USER="${UDR_USER:-root}"
UDR_PASS="${UDR_PASS:-!#o#It0S!#o#It0S}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Target: $UDR_USER@$UDR_HOST"
echo "Script: $SCRIPT_DIR/deploy-log-rules.py"
echo ""

# Check if paramiko is installed
if ! python3 -c "import paramiko" 2>/dev/null; then
    echo "Installing paramiko..."
    python3 -m pip install --user paramiko
fi

# Test connectivity first
echo "Testing connectivity..."
if timeout 5 bash -c "echo > /dev/tcp/$UDR_HOST/22" 2>/dev/null; then
    echo "SSH port is reachable"
else
    echo "ERROR: Cannot reach $UDR_HOST:22"
    echo ""
    echo "Troubleshooting:"
    echo "1. Verify SSH is enabled on UDR"
    echo "2. If using WAN IP (47.202.19.61), enable SSH on WAN in UniFi settings"
    echo "3. If using LAN IP (192.168.21.1), ensure you have network route"
    echo "4. Check firewall rules"
    exit 1
fi

echo ""
echo "====== DRY RUN (Preview) ======"
python3 "$SCRIPT_DIR/deploy-log-rules.py" \
    --host "$UDR_HOST" \
    --user "$UDR_USER" \
    --pass "$UDR_PASS" \
    --dry-run

echo ""
echo "====== ACTUAL DEPLOYMENT ======"
read -p "Proceed with deployment? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    python3 "$SCRIPT_DIR/deploy-log-rules.py" \
        --host "$UDR_HOST" \
        --user "$UDR_USER" \
        --pass "$UDR_PASS"

    echo ""
    echo "====== NEXT STEPS ======"
    echo "1. Configure syslog forwarding on UDR:"
    echo "   Settings > System > Logging > Remote Logging"
    echo "   Server: 192.168.18.10"
    echo "   Port: 514"
    echo "   Protocol: UDP"
    echo ""
    echo "2. Test log forwarding:"
    echo "   ssh $UDR_USER@$UDR_HOST 'logger -t UNIFI-TEST \"Test message from UDR\"'"
    echo ""
    echo "3. Verify logs on NAS:"
    echo "   ssh nas 'tail -f /var/log/messages | grep UNIFI'"
    echo ""
    echo "Deployment complete!"
else
    echo "Deployment cancelled"
    exit 0
fi
