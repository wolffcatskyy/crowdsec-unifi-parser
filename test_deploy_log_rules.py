"""Unit tests for deploy-log-rules.py."""
import importlib
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

# Add parent directory to path so deploy-log-rules can be imported as a module
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

deploy_log_rules_mod = importlib.import_module("deploy-log-rules")


class TestDeployLogRules(unittest.TestCase):
    def test_chain_to_short(self):
        self.assertEqual(
            deploy_log_rules_mod.chain_to_short("UBIOS_WAN_LOCAL_USER"), "WAN_LOCAL"
        )
        self.assertEqual(
            deploy_log_rules_mod.chain_to_short("UBIOS_WAN_IN_USER"), "WAN_IN"
        )
        self.assertEqual(
            deploy_log_rules_mod.chain_to_short("CUSTOM_CHAIN"), "CUSTOM_CHAIN"
        )

    def test_build_log_command(self):
        drop_rule_invalid = {
            "index": 2,
            "is_invalid": True,
            "raw": "-A UBIOS_WAN_LOCAL_USER -m conntrack --ctstate INVALID -j DROP",
        }
        cmd = deploy_log_rules_mod.build_log_command(
            "UBIOS_WAN_LOCAL_USER", drop_rule_invalid
        )
        self.assertIn("iptables -I UBIOS_WAN_LOCAL_USER 2", cmd)
        self.assertIn("-m conntrack --ctstate INVALID", cmd)
        self.assertIn("--limit 10/min", cmd)
        self.assertIn('/* CROWDSEC_LOG */' if '/*' in cmd else 'CROWDSEC_LOG', cmd)
        self.assertIn('[UNIFI-WAN_LOCAL-D-INVALID]', cmd)

        drop_rule_all = {
            "index": 5,
            "is_invalid": False,
            "raw": "-A UBIOS_WAN_LAN_USER -j DROP",
        }
        cmd_all = deploy_log_rules_mod.build_log_command(
            "UBIOS_WAN_LAN_USER", drop_rule_all
        )
        self.assertIn("iptables -I UBIOS_WAN_LAN_USER 5", cmd_all)
        self.assertIn('[UNIFI-WAN_LAN-D-ALL]', cmd_all)

    def test_parse_drop_rules(self):
        mock_client = MagicMock()
        iptables_s_output = (
            "-N UBIOS_WAN_LOCAL_USER\n"
            "-A UBIOS_WAN_LOCAL_USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A UBIOS_WAN_LOCAL_USER -m conntrack --ctstate INVALID -j DROP\n"
            "-A UBIOS_WAN_LOCAL_USER -p udp -m udp --dport 53 -j ACCEPT\n"
            "-A UBIOS_WAN_LOCAL_USER -j DROP\n"
        )
        with patch.object(
            deploy_log_rules_mod, "run_cmd", return_value=(0, iptables_s_output, "")
        ):
            rules = deploy_log_rules_mod.parse_drop_rules(
                mock_client, "UBIOS_WAN_LOCAL_USER"
            )
            self.assertEqual(len(rules), 2)
            self.assertEqual(rules[0]["index"], 2)
            self.assertTrue(rules[0]["is_invalid"])
            self.assertEqual(rules[1]["index"], 4)
            self.assertFalse(rules[1]["is_invalid"])

    def test_cleanup_existing_rules_dry_run_single_pass(self):
        mock_client = MagicMock()
        iptables_l_output = (
            "Chain UBIOS_WAN_LOCAL_USER (1 references)\n"
            "num  target prot opt source destination\n"
            "1    LOG    all  --  0.0.0.0/0 0.0.0.0/0 /* CROWDSEC_LOG */ LOG level 4 prefix \"[UNIFI-WAN_LOCAL-D-INVALID] \"\n"
            "2    DROP   all  --  0.0.0.0/0 0.0.0.0/0 ctstate INVALID\n"
            "3    LOG    all  --  0.0.0.0/0 0.0.0.0/0 /* CROWDSEC_LOG */ LOG level 4 prefix \"[UNIFI-WAN_LOCAL-D-ALL] \"\n"
            "4    DROP   all  --  0.0.0.0/0 0.0.0.0/0\n"
        )

        with patch.object(
            deploy_log_rules_mod, "CHAINS", ["UBIOS_WAN_LOCAL_USER"]
        ), patch.object(
            deploy_log_rules_mod, "run_cmd", return_value=(0, iptables_l_output, "")
        ) as mock_run:
            removed = deploy_log_rules_mod.cleanup_existing_rules(
                mock_client, dry_run=True
            )
            # Should count exactly 2 rules in a single pass without looping 200 times
            self.assertEqual(removed, 2)
            self.assertEqual(mock_run.call_count, 1)

    def test_cleanup_existing_rules_live_mode(self):
        mock_client = MagicMock()
        # First call has 1 rule, second call is empty
        calls = [
            (
                0,
                "Chain UBIOS_WAN_LOCAL_USER (1 references)\n"
                "num  target prot opt source destination\n"
                "1    LOG    all  --  0.0.0.0/0 0.0.0.0/0 /* CROWDSEC_LOG */ LOG level 4 prefix \"[UNIFI-WAN_LOCAL-D-INVALID] \"\n"
                "2    DROP   all  --  0.0.0.0/0 0.0.0.0/0 ctstate INVALID\n",
                "",
            ),
            (0, "", ""),  # delete command response
            (
                0,
                "Chain UBIOS_WAN_LOCAL_USER (1 references)\n"
                "num  target prot opt source destination\n"
                "1    DROP   all  --  0.0.0.0/0 0.0.0.0/0 ctstate INVALID\n",
                "",
            ),
        ]

        with patch.object(
            deploy_log_rules_mod, "CHAINS", ["UBIOS_WAN_LOCAL_USER"]
        ), patch.object(
            deploy_log_rules_mod, "run_cmd", side_effect=calls
        ) as mock_run:
            removed = deploy_log_rules_mod.cleanup_existing_rules(
                mock_client, dry_run=False
            )
            self.assertEqual(removed, 1)
            mock_run.assert_has_calls(
                [
                    call(
                        mock_client,
                        "iptables -L UBIOS_WAN_LOCAL_USER --line-numbers -n 2>/dev/null",
                    ),
                    call(mock_client, "iptables -D UBIOS_WAN_LOCAL_USER 1"),
                    call(
                        mock_client,
                        "iptables -L UBIOS_WAN_LOCAL_USER --line-numbers -n 2>/dev/null",
                    ),
                ]
            )


if __name__ == "__main__":
    unittest.main()
