from __future__ import annotations

import ipaddress
import hashlib
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import update_microsoft_rules as updater  # noqa: E402
import update_apple_rules as apple_updater  # noqa: E402
import update_google_rules as google_updater  # noqa: E402


def active_lines(path: Path):
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip() and not line.lstrip().startswith(("#", "//", ";"))
    ]


class RepositoryOutputTests(unittest.TestCase):
    def test_generated_apple_outputs_match_source(self):
        apple_updater.check()

    def test_generated_microsoft_outputs_match_source(self):
        updater.check()

    def test_generated_google_outputs_match_source(self):
        google_updater.check()

    def test_all_published_rule_files_have_declared_syntax(self):
        allowed = {
            "DOMAIN",
            "DOMAIN-SUFFIX",
            "DOMAIN-KEYWORD",
            "DOMAIN-WILDCARD",
            "IP-CIDR",
            "IP-CIDR6",
            "IP-ASN",
            "PROCESS-NAME",
        }
        for path in sorted((ROOT / "dist").glob("*.txt")):
            with self.subTest(path=path.name):
                lines = active_lines(path)
                if path.name.endswith("_domainset.txt"):
                    for line in lines:
                        self.assertNotIn(",", line)
                        self.assertFalse(re.search(r"\s", line))
                elif path.name.endswith("_ruleset.txt"):
                    for line in lines:
                        fields = [part.strip() for part in line.split(",")]
                        self.assertIn(fields[0], allowed)
                        self.assertGreaterEqual(len(fields), 2)
                        if fields[0] in {"IP-CIDR", "IP-CIDR6"}:
                            network = ipaddress.ip_network(fields[1], strict=True)
                            self.assertEqual(fields[0], "IP-CIDR6" if network.version == 6 else "IP-CIDR")
                            if path.name in {
                                "microsoft_generated_ruleset.txt",
                                "apple_generated_ip_ruleset.txt",
                                "google_generated_ruleset.txt",
                            }:
                                self.assertIn("no-resolve", fields[2:])
                else:
                    self.fail(f"published filename does not declare its type: {path.name}")

    def test_legacy_microsoft_ip_filename_is_removed(self):
        self.assertFalse((ROOT / "dist" / "microsoft_generated_ip_ruleset.txt").exists())

    def test_legacy_google_ip_filename_is_removed(self):
        self.assertFalse((ROOT / "dist" / "google_generated_ip_ruleset.txt").exists())

    def test_legacy_google_domains_are_preserved_manually(self):
        lines = active_lines(ROOT / "dist" / "google_manual_domainset.txt")
        payload = ("\n".join(lines) + "\n").encode()
        self.assertEqual(len(lines), 1120)
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            "1270ff385c44e9ac70f6486aa3c97864600427fdfab69b9d24001859fa03c8af",
        )

    def test_public_rules_omit_private_policy_names_and_global_curl_override(self):
        published = "\n".join(
            path.read_text(encoding="utf-8-sig")
            for path in sorted((ROOT / "dist").glob("*.txt"))
        )
        for private_term in ("12VPX", "Bwgyus", "Gate", "Los Angeles"):
            with self.subTest(private_term=private_term):
                self.assertNotIn(private_term, published)
        self.assertNotIn(
            "PROCESS-NAME,/usr/bin/curl",
            active_lines(ROOT / "dist" / "high_traffic_ruleset.txt"),
        )


if __name__ == "__main__":
    unittest.main()
