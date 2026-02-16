#!/usr/bin/env bash
#
# install.sh — Install CrowdSec UniFi parsers, scenarios, and acquisition config.
#
# Usage:
#   sudo ./install.sh                  # Install parsers + acquisition config
#   sudo ./install.sh --with-deploy    # Also deploy LOG rules to UDM
#
# Requirements:
#   - CrowdSec installed and running
#   - Root/sudo access (to write to CrowdSec config directories)
#   - For --with-deploy: Python 3 + paramiko (pip3 install paramiko)

set -euo pipefail

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

CROWDSEC_CONFIG_DIR="/etc/crowdsec"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WITH_DEPLOY=false

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --with-deploy)
            WITH_DEPLOY=true
            shift
            ;;
        --config-dir)
            CROWDSEC_CONFIG_DIR="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Install CrowdSec UniFi parsers and acquisition config."
            echo ""
            echo "Options:"
            echo "  --with-deploy     Also run deploy-log-rules.py on UDM"
            echo "  --config-dir DIR  CrowdSec config directory (default: /etc/crowdsec)"
            echo "  -h, --help        Show this help"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

info "CrowdSec UniFi Parser Installer"
echo ""

# Check if CrowdSec config directory exists
if [[ ! -d "$CROWDSEC_CONFIG_DIR" ]]; then
    error "CrowdSec config directory not found: $CROWDSEC_CONFIG_DIR"
    error "Is CrowdSec installed? Try: --config-dir /path/to/crowdsec/config"
    exit 1
fi

# Check if we're running as root (needed to write to /etc/crowdsec)
if [[ $EUID -ne 0 ]]; then
    warn "Not running as root. You may get permission errors."
    warn "Re-run with: sudo $0 $*"
fi

# Check if cscli is available
if ! command -v cscli &> /dev/null; then
    warn "cscli not found in PATH. Will install files manually."
    warn "If CrowdSec is in Docker, you may need to copy files into the container."
fi

# ---------------------------------------------------------------------------
# Install parsers
# ---------------------------------------------------------------------------

info "Installing parsers..."

# s00-raw parsers
mkdir -p "$CROWDSEC_CONFIG_DIR/parsers/s00-raw"
cp "$SCRIPT_DIR/parsers/s00-raw/unifi-logs.yaml" "$CROWDSEC_CONFIG_DIR/parsers/s00-raw/"
success "Installed s00-raw/unifi-logs.yaml"

cp "$SCRIPT_DIR/parsers/s00-raw/cef-logs.yaml" "$CROWDSEC_CONFIG_DIR/parsers/s00-raw/"
success "Installed s00-raw/cef-logs.yaml"

# s01-parse parsers
mkdir -p "$CROWDSEC_CONFIG_DIR/parsers/s01-parse"
cp "$SCRIPT_DIR/parsers/s01-parse/unifi-cef.yaml" "$CROWDSEC_CONFIG_DIR/parsers/s01-parse/"
success "Installed s01-parse/unifi-cef.yaml"

cp "$SCRIPT_DIR/parsers/s01-parse/dropbear-logs.yaml" "$CROWDSEC_CONFIG_DIR/parsers/s01-parse/"
success "Installed s01-parse/dropbear-logs.yaml"

# ---------------------------------------------------------------------------
# Install scenarios
# ---------------------------------------------------------------------------

info "Installing scenarios..."

mkdir -p "$CROWDSEC_CONFIG_DIR/scenarios"
cp "$SCRIPT_DIR/scenarios/iptables-scan-multi_ports.yaml" "$CROWDSEC_CONFIG_DIR/scenarios/"
success "Installed scenarios/iptables-scan-multi_ports.yaml"

cp "$SCRIPT_DIR/scenarios/dropbear-bf.yaml" "$CROWDSEC_CONFIG_DIR/scenarios/"
success "Installed scenarios/dropbear-bf.yaml"

cp "$SCRIPT_DIR/scenarios/unifi-ips-alert.yaml" "$CROWDSEC_CONFIG_DIR/scenarios/"
success "Installed scenarios/unifi-ips-alert.yaml"

# ---------------------------------------------------------------------------
# Install collection
# ---------------------------------------------------------------------------

info "Installing collection..."

mkdir -p "$CROWDSEC_CONFIG_DIR/collections"
cp "$SCRIPT_DIR/collections/unifi.yaml" "$CROWDSEC_CONFIG_DIR/collections/"
success "Installed collections/unifi.yaml"

# ---------------------------------------------------------------------------
# Install acquisition config
# ---------------------------------------------------------------------------

info "Installing acquisition config..."

mkdir -p "$CROWDSEC_CONFIG_DIR/acquis.d"

if [[ -f "$CROWDSEC_CONFIG_DIR/acquis.d/unifi.yaml" ]]; then
    warn "acquis.d/unifi.yaml already exists. Backing up to unifi.yaml.bak"
    cp "$CROWDSEC_CONFIG_DIR/acquis.d/unifi.yaml" "$CROWDSEC_CONFIG_DIR/acquis.d/unifi.yaml.bak"
fi

cp "$SCRIPT_DIR/acquis.d/unifi.yaml" "$CROWDSEC_CONFIG_DIR/acquis.d/"
success "Installed acquis.d/unifi.yaml"

echo ""
warn "IMPORTANT: Edit $CROWDSEC_CONFIG_DIR/acquis.d/unifi.yaml to match your log path!"
echo ""

# ---------------------------------------------------------------------------
# Reload CrowdSec
# ---------------------------------------------------------------------------

if command -v cscli &> /dev/null; then
    info "Reloading CrowdSec..."
    if systemctl is-active --quiet crowdsec 2>/dev/null; then
        systemctl reload crowdsec
        success "CrowdSec reloaded via systemd"
    elif command -v docker &> /dev/null; then
        warn "CrowdSec may be running in Docker. Restart your container to pick up changes."
        warn "  docker restart crowdsec"
    else
        warn "Could not detect CrowdSec service. Restart CrowdSec manually."
    fi
else
    warn "cscli not found. Restart CrowdSec manually to load new parsers."
fi

# ---------------------------------------------------------------------------
# Optional: Deploy LOG rules to UDM
# ---------------------------------------------------------------------------

if [[ "$WITH_DEPLOY" == "true" ]]; then
    echo ""
    info "Deploying LOG rules to UDM..."

    if ! command -v python3 &> /dev/null; then
        error "python3 not found. Cannot run deploy-log-rules.py"
        exit 1
    fi

    if ! python3 -c "import paramiko" 2>/dev/null; then
        error "paramiko not installed. Install with: pip3 install paramiko"
        exit 1
    fi

    echo ""
    echo "Enter UDM connection details:"
    read -rp "  UDM IP address [192.168.1.1]: " UDM_HOST
    UDM_HOST="${UDM_HOST:-192.168.1.1}"
    read -rp "  SSH username [root]: " UDM_USER
    UDM_USER="${UDM_USER:-root}"
    read -rsp "  SSH password: " UDM_PASS
    echo ""

    export UDM_HOST UDM_USER UDM_PASS
    python3 "$SCRIPT_DIR/deploy-log-rules.py" --host "$UDM_HOST" --user "$UDM_USER" --pass "$UDM_PASS"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "=================================================="
echo -e "${GREEN}Installation complete!${NC}"
echo "=================================================="
echo ""
echo "Installed:"
echo "  - parsers/s00-raw/unifi-logs.yaml    (raw UniFi syslog parser)"
echo "  - parsers/s00-raw/cef-logs.yaml      (CEF format parser)"
echo "  - parsers/s01-parse/unifi-cef.yaml   (UniFi CEF event parser)"
echo "  - parsers/s01-parse/dropbear-logs.yaml (UDM SSH auth parser)"
echo "  - scenarios/iptables-scan-multi_ports.yaml (port scan detection)"
echo "  - scenarios/dropbear-bf.yaml             (SSH brute force detection)"
echo "  - scenarios/unifi-ips-alert.yaml       (IPS/Threat Management detection)"
echo "  - collections/unifi.yaml             (collection bundle)"
echo "  - acquis.d/unifi.yaml                (log acquisition config)"
echo ""
echo "Next steps:"
echo "  1. Edit $CROWDSEC_CONFIG_DIR/acquis.d/unifi.yaml (set your log path)"
echo "  2. Deploy LOG rules on your UDM:"
echo "     python3 deploy-log-rules.py --host <UDM_IP> --pass <PASSWORD>"
echo "  3. Set up syslog forwarding from UDM to your CrowdSec host"
echo "  4. Restart CrowdSec and verify:"
echo "     cscli metrics"
echo ""
