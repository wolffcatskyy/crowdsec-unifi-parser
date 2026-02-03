#!/usr/bin/env python3
"""
deploy-log-rules.py — Deploy iptables LOG rules on UniFi Dream Machines for CrowdSec visibility.

PURPOSE:
    Inserts iptables LOG rules immediately before every DROP rule in the UDM's
    WAN-facing firewall chains. This gives CrowdSec (and kern.log) visibility into
    blocked traffic without changing any actual firewall behavior.

WHEN TO RUN:
    - After every UDM firmware update (UniFi regenerates iptables on upgrade)
    - After CrowdSec bouncer restarts that rebuild firewall rules
    - After any manual iptables changes on the UDM
    - Idempotent: safe to run repeatedly; cleans up old rules first

WHAT IT DOES:
    1. SSHes into UDM via paramiko keyboard-interactive auth
    2. Removes all existing CROWDSEC_LOG-commented iptables rules (idempotent cleanup)
    3. Enumerates DROP rules in these chains:
         UBIOS_WAN_LOCAL_USER, UBIOS_WAN_LAN_USER, UBIOS_WAN_IN_USER,
         UBIOS_WAN_DMZ_USER, UBIOS_WAN_GUEST_USER, UBIOS_WAN_VPN_USER,
         UBIOS_WAN_WAN_USER
    4. Inserts a LOG rule immediately before each DROP rule with:
         - Rate limit: 10/min burst 20
         - Comment: CROWDSEC_LOG
         - Prefix: [UNIFI-{chain_short}-D-{INVALID|ALL}]
         - Log level 4 (warning)
    5. Inserts from bottom to top within each chain to preserve rule indices
    6. Verifies rules were inserted and reports results

LOG FORMAT EXAMPLES:
    [UNIFI-WAN_LOCAL-D-INVALID] — conntrack INVALID state drop
    [UNIFI-WAN_LAN-D-ALL]      — catch-all drop at chain end

EXIT CODES:
    0 — Success (rules deployed and verified)
    1 — Failure (SSH error, iptables error, verification failed)
"""

import sys
import os
import re
import time
import logging
import argparse

try:
    import paramiko
except ImportError:
    print("ERROR: paramiko not installed. Install with: pip3 install paramiko", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CHAINS = [
    "UBIOS_WAN_LOCAL_USER",
    "UBIOS_WAN_LAN_USER",
    "UBIOS_WAN_IN_USER",
    "UBIOS_WAN_DMZ_USER",
    "UBIOS_WAN_GUEST_USER",
    "UBIOS_WAN_VPN_USER",
    "UBIOS_WAN_WAN_USER",
]

COMMENT_MARKER = "CROWDSEC_LOG"
RATE_LIMIT = "10/min"
RATE_BURST = "20"
LOG_LEVEL = "4"

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("deploy-log-rules")

# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------


def parse_args():
    """Parse command-line arguments for UDM connection details."""
    parser = argparse.ArgumentParser(
        description="Deploy iptables LOG rules on UniFi Dream Machines for CrowdSec visibility.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Environment variables (override defaults, overridden by CLI args):
  UDM_HOST     UDM IP address (default: 192.168.1.1)
  UDM_USER     SSH username (default: root)
  UDM_PASS     SSH password (required if not passed via --pass)
  UDM_PORT     SSH port (default: 22)

Examples:
  %(prog)s --host 192.168.1.1 --pass MyPassword
  UDM_PASS=MyPassword %(prog)s --host 10.0.0.1
  %(prog)s --host 192.168.1.1 --pass MyPassword --dry-run
""",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("UDM_HOST", "192.168.1.1"),
        help="UDM IP address (default: $UDM_HOST or 192.168.1.1)",
    )
    parser.add_argument(
        "--user",
        default=os.environ.get("UDM_USER", "root"),
        help="SSH username (default: $UDM_USER or root)",
    )
    parser.add_argument(
        "--pass",
        dest="password",
        default=os.environ.get("UDM_PASS", ""),
        help="SSH password (default: $UDM_PASS)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("UDM_PORT", "22")),
        help="SSH port (default: $UDM_PORT or 22)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    if not args.password:
        parser.error(
            "SSH password required. Use --pass, set UDM_PASS environment variable, "
            "or pass it via stdin."
        )

    return args


# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------


def create_ssh_client(host, port, user, password):
    """Create and return an authenticated paramiko SSH client to the UDM.

    Uses keyboard-interactive authentication, which is the method the UDM
    expects for root login.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # keyboard-interactive handler: responds to all prompts with the password
    def kb_interactive_handler(title, instructions, prompt_list):
        return [password] * len(prompt_list)

    log.info("Connecting to UDM at %s:%d as %s ...", host, port, user)

    try:
        # Attempt transport-level connect for keyboard-interactive
        transport = paramiko.Transport((host, port))
        transport.connect()
        transport.auth_interactive(user, kb_interactive_handler)
        client._transport = transport
        log.info("SSH connection established (keyboard-interactive auth)")
        return client
    except paramiko.AuthenticationException:
        log.warning("keyboard-interactive auth failed, trying password auth ...")
        try:
            transport.close()
        except Exception:
            pass
        # Fallback to password auth
        client.connect(
            host,
            port=port,
            username=user,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=15,
        )
        log.info("SSH connection established (password auth)")
        return client


def run_cmd(client, cmd, timeout=30):
    """Execute a command over SSH and return (exit_code, stdout, stderr)."""
    transport = client.get_transport()
    if transport is None or not transport.is_active():
        raise RuntimeError("SSH transport is not active")

    channel = transport.open_session()
    channel.settimeout(timeout)
    channel.exec_command(cmd)

    stdout_chunks = []
    stderr_chunks = []

    while True:
        if channel.recv_ready():
            stdout_chunks.append(channel.recv(65536).decode("utf-8", errors="replace"))
        if channel.recv_stderr_ready():
            stderr_chunks.append(channel.recv_stderr(65536).decode("utf-8", errors="replace"))
        if channel.exit_status_ready():
            # Drain remaining data
            while channel.recv_ready():
                stdout_chunks.append(channel.recv(65536).decode("utf-8", errors="replace"))
            while channel.recv_stderr_ready():
                stderr_chunks.append(channel.recv_stderr(65536).decode("utf-8", errors="replace"))
            break
        time.sleep(0.05)

    exit_code = channel.recv_exit_status()
    channel.close()

    return exit_code, "".join(stdout_chunks), "".join(stderr_chunks)


def run_cmd_checked(client, cmd, description="command", timeout=30):
    """Run a command, log it, and raise on non-zero exit."""
    exit_code, stdout, stderr = run_cmd(client, cmd, timeout=timeout)
    if exit_code != 0:
        log.error("%s failed (exit %d): %s", description, exit_code, stderr.strip())
        raise RuntimeError(f"{description} failed with exit code {exit_code}: {stderr.strip()}")
    return stdout


# ---------------------------------------------------------------------------
# Chain name helpers
# ---------------------------------------------------------------------------


def chain_to_short(chain_name):
    """Convert UBIOS_WAN_LOCAL_USER -> WAN_LOCAL etc."""
    short = chain_name
    if short.startswith("UBIOS_"):
        short = short[6:]
    if short.endswith("_USER"):
        short = short[:-5]
    return short


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def cleanup_existing_rules(client, dry_run=False):
    """Remove all iptables rules with the CROWDSEC_LOG comment marker.

    Iterates multiple passes because removing a rule shifts indices.
    Returns the total number of rules removed.
    """
    total_removed = 0

    for chain in CHAINS:
        pass_count = 0
        while True:
            pass_count += 1
            if pass_count > 200:
                log.error("Cleanup loop exceeded 200 passes for %s, aborting", chain)
                break

            # List rules with line numbers
            exit_code, stdout, stderr = run_cmd(
                client, f"iptables -L {chain} --line-numbers -n 2>/dev/null"
            )
            if exit_code != 0:
                log.warning("Chain %s does not exist or cannot be listed, skipping cleanup", chain)
                break

            # Find first line with our marker (always delete lowest index first)
            found = False
            for line in stdout.splitlines():
                if COMMENT_MARKER in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        rule_num = parts[0]
                        if dry_run:
                            log.info("  [DRY RUN] Would remove rule #%s from %s", rule_num, chain)
                        else:
                            log.info("  Removing rule #%s from %s", rule_num, chain)
                            rc, _, err = run_cmd(client, f"iptables -D {chain} {rule_num}")
                            if rc != 0:
                                log.error("  Failed to remove rule #%s from %s: %s", rule_num, chain, err)
                        total_removed += 1
                        found = True
                        break  # Restart scan since indices shifted

            if not found:
                break

    return total_removed


def parse_drop_rules(client, chain):
    """Parse a chain and return a list of DROP rule dicts with their indices.

    Each dict has:
        index:      int (1-based rule number)
        is_invalid: bool (True if rule matches conntrack INVALID state)
        raw:        str (raw iptables -S output line, for debugging)
    """
    # Use iptables -S to get machine-parseable output
    exit_code, stdout, stderr = run_cmd(client, f"iptables -S {chain} 2>/dev/null")
    if exit_code != 0:
        log.warning("Chain %s does not exist, skipping", chain)
        return []

    drop_rules = []
    rule_index = 0

    for line in stdout.splitlines():
        line = line.strip()
        # -S output lines starting with -A are actual rules in the chain
        if not line.startswith("-A "):
            continue
        rule_index += 1

        if "-j DROP" not in line:
            continue

        is_invalid = bool(re.search(r"--ctstate\s+\S*INVALID", line))
        drop_rules.append({
            "index": rule_index,
            "is_invalid": is_invalid,
            "raw": line,
        })

    return drop_rules


def build_log_command(chain, drop_rule):
    """Build the full iptables command string to insert a LOG rule before a DROP rule.

    Replicates the DROP rule's match criteria so the LOG rule fires on the
    same packets, then appends rate limiting, comment, and LOG target.
    """
    short = chain_to_short(chain)
    suffix = "INVALID" if drop_rule["is_invalid"] else "ALL"
    prefix = f"[UNIFI-{short}-D-{suffix}]"

    raw = drop_rule["raw"]

    # Extract the match portion from the raw -S line:
    #   -A CHAINNAME [match criteria] -j DROP
    # Strip "-A CHAINNAME" from the front
    match_portion = re.sub(r"^-A\s+\S+\s*", "", raw)
    # Strip "-j DROP" (and any trailing content) from the end
    match_portion = re.sub(r"\s*-j\s+DROP.*$", "", match_portion)
    match_portion = match_portion.strip()

    # Build the iptables insert command
    cmd_parts = [f"iptables -I {chain} {drop_rule['index']}"]

    if match_portion:
        cmd_parts.append(match_portion)

    # Rate limit module
    cmd_parts.append(f"-m limit --limit {RATE_LIMIT} --limit-burst {RATE_BURST}")

    # Comment module
    cmd_parts.append(f'-m comment --comment "{COMMENT_MARKER}"')

    # LOG target
    cmd_parts.append(f'-j LOG --log-prefix "{prefix} " --log-level {LOG_LEVEL}')

    return " ".join(cmd_parts)


def deploy_log_rules(client, dry_run=False):
    """Deploy LOG rules before every DROP rule in all configured chains.

    Inserts from bottom to top within each chain to preserve rule indices.
    Returns (deployed_count, chain_summary_dict).
    """
    total_deployed = 0
    chain_summary = {}

    for chain in CHAINS:
        short = chain_to_short(chain)
        log.info("Processing chain: %s (%s)", chain, short)

        drop_rules = parse_drop_rules(client, chain)
        if not drop_rules:
            log.info("  No DROP rules found in %s", chain)
            chain_summary[short] = 0
            continue

        log.info("  Found %d DROP rule(s) in %s", len(drop_rules), chain)

        # Insert from bottom to top to preserve rule indices.
        # When we insert at index N, all rules at N and above shift down by 1.
        # By processing highest index first, we avoid affecting lower indices.
        chain_deployed = 0
        for drop_rule in reversed(drop_rules):
            cmd = build_log_command(chain, drop_rule)
            suffix = "INVALID" if drop_rule["is_invalid"] else "ALL"
            desc = f"LOG before DROP #{drop_rule['index']} ({suffix}) in {chain}"

            if dry_run:
                log.info("  [DRY RUN] Would insert: %s", desc)
                log.info("  [DRY RUN] Command: %s", cmd)
            else:
                log.info("  Inserting: %s", desc)
                log.debug("  Command: %s", cmd)
                try:
                    run_cmd_checked(client, cmd, description=desc)
                except RuntimeError as e:
                    log.error("  FAILED to insert rule: %s", e)
                    continue

            total_deployed += 1
            chain_deployed += 1

        chain_summary[short] = chain_deployed

    return total_deployed, chain_summary


def verify_rules(client):
    """Verify CROWDSEC_LOG rules are present in all chains.

    Returns total count of verified LOG rules.
    """
    total_found = 0
    for chain in CHAINS:
        exit_code, stdout, _ = run_cmd(client, f"iptables -S {chain} 2>/dev/null")
        if exit_code != 0:
            continue
        count = stdout.count(COMMENT_MARKER)
        if count > 0:
            short = chain_to_short(chain)
            log.info("  Verified: %d LOG rule(s) in %s", count, short)
        total_found += count
    return total_found


def check_kern_log(client):
    """Check for recent UNIFI log entries in kern.log/messages.

    Returns (sample_lines_str, logpath) or (None, None) if nothing found.
    """
    for logpath in ["/var/log/messages", "/var/log/kern.log", "/var/log/syslog"]:
        exit_code, stdout, _ = run_cmd(
            client,
            f'tail -100 {logpath} 2>/dev/null | grep "UNIFI-" | tail -5',
        )
        if exit_code == 0 and stdout.strip():
            return stdout.strip(), logpath

    return None, None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    log.info("=" * 70)
    log.info("UDM — Deploy CrowdSec iptables LOG rules")
    if args.dry_run:
        log.info("*** DRY RUN MODE — no changes will be made ***")
    log.info("=" * 70)

    client = None
    try:
        # ----- Step 1: Connect -----
        client = create_ssh_client(args.host, args.port, args.user, args.password)

        hostname = run_cmd_checked(client, "hostname", "hostname check").strip()
        log.info("Connected to: %s", hostname)

        # ----- Step 2: Cleanup existing rules (idempotent) -----
        log.info("")
        log.info("--- Phase 1: Cleanup existing CROWDSEC_LOG rules ---")
        removed = cleanup_existing_rules(client, dry_run=args.dry_run)
        if removed > 0:
            log.info("Removed %d existing CROWDSEC_LOG rule(s)", removed)
        else:
            log.info("No existing CROWDSEC_LOG rules to remove (clean slate)")

        # ----- Step 3: Deploy new LOG rules -----
        log.info("")
        log.info("--- Phase 2: Deploy LOG rules before DROP rules ---")
        deployed, chain_summary = deploy_log_rules(client, dry_run=args.dry_run)

        # ----- Step 4: Verify -----
        log.info("")
        log.info("--- Phase 3: Verification ---")
        if args.dry_run:
            log.info("  [DRY RUN] Skipping verification")
            verified = deployed
        else:
            verified = verify_rules(client)

        # ----- Step 5: Check for log entries -----
        log.info("")
        log.info("--- Phase 4: Check kern.log for entries ---")
        sample_lines, logpath = check_kern_log(client)
        if sample_lines:
            log.info("Found recent UNIFI log entries in %s:", logpath)
            for line in sample_lines.splitlines():
                log.info("  %s", line.strip())
        else:
            log.info("No UNIFI log entries found yet (normal if just deployed)")
            log.info("Entries will appear in kern.log/messages when traffic hits DROP rules")

        # ----- Summary -----
        log.info("")
        log.info("=" * 70)
        log.info("SUMMARY%s", " (DRY RUN)" if args.dry_run else "")
        log.info("=" * 70)
        log.info("Rules removed (cleanup):  %d", removed)
        log.info("Rules deployed:           %d", deployed)
        log.info("Rules verified:           %d", verified)
        log.info("")
        log.info("Per-chain breakdown:")
        for short, count in sorted(chain_summary.items()):
            log.info("  %-20s %d LOG rule(s)", short, count)

        if not args.dry_run and deployed != verified:
            log.error("")
            log.error(
                "MISMATCH: Deployed %d but verified %d -- something went wrong!",
                deployed, verified,
            )
            return 1

        if deployed == 0:
            log.warning("")
            log.warning("No DROP rules found in any chain. Are the chains populated?")
            log.warning("This may be normal if CrowdSec bouncer hasn't created rules yet.")
            return 0

        log.info("")
        log.info(
            "SUCCESS: %d LOG rules deployed across %d chain(s)",
            deployed,
            len([v for v in chain_summary.values() if v > 0]),
        )
        return 0

    except Exception as e:
        log.error("FATAL: %s", e)
        import traceback
        traceback.print_exc()
        return 1

    finally:
        if client:
            try:
                transport = client.get_transport()
                if transport:
                    transport.close()
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
