from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import update_apple_rules as updater  # noqa: E402


ARTICLE = """<!doctype html>
<html><head>
<link rel="canonical" href="https://support.apple.com/en-us/101555">
</head><body><div id="sections">
<h1>Use Apple products on enterprise networks</h1>
<h2 id="devicesetup">Device setup</h2>
<table><tbody>
<tr><th>Hosts</th><th>Port</th><th>Protocol</th><th>OS</th><th>Description</th><th>Supports proxies</th></tr>
<tr><td>*.Example.com.</td><td>443, 80</td><td>TCP/UDP</td><td>iOS &amp; macOS</td><td>A &amp; B</td><td><a href="#proxy">Learn more</a></td></tr>
</tbody></table>
<h2 id="firewalls">Firewalls</h2>
<p>Allow outbound connections to *.apple.com.</p>
<p>For IPv4, use 17.0.0.0/8.</p>
<ul><li>2403:300::/32</li><li>2620:149::/32</li></ul>
<h2 id="recentchanges">Recent changes</h2>
<ul><li>July 2026: Updated endpoints.</li></ul>
</div>
<time dateTime=August 07, 2026itemprop='datePublished'>August 07, 2026</time>
</body></html>"""


def parse_fixture(html: str = ARTICLE):
    with (
        mock.patch.object(
            updater,
            "REQUIRED_SECTION_IDS",
            {"devicesetup", "firewalls", "recentchanges"},
        ),
        mock.patch.object(updater, "MIN_TABLES", 1),
        mock.patch.object(updater, "MIN_ROWS", 1),
        mock.patch.object(updater, "MIN_UNIQUE_HOSTS", 1),
    ):
        return updater.parse_article(html)


class AppleRuleGeneratorTests(unittest.TestCase):
    def test_classifies_exact_and_standard_wildcard(self):
        self.assertEqual(
            updater.classify_host("Login.Apple.com."),
            ("login.apple.com", "login.apple.com"),
        )
        self.assertEqual(
            updater.classify_host("*.Example.com"),
            ("*.example.com", ".example.com"),
        )
        for value in (
            "https://apple.com",
            "apple.com/path",
            "autodiscover.*.apple.com",
            "*cdn.apple.com",
        ):
            with self.subTest(value=value), self.assertRaises(updater.SourceDataError):
                updater.classify_host(value)

    def test_parses_tables_firewall_metadata_and_malformed_datetime_attribute(self):
        parsed = parse_fixture()
        self.assertEqual(parsed["published_date"], "2026-08-07")
        self.assertEqual(parsed["firewall"]["hostname_patterns"], ["*.apple.com"])
        self.assertEqual(
            parsed["firewall"]["ip_ranges"],
            ["17.0.0.0/8", "2403:300::/32", "2620:149::/32"],
        )
        self.assertEqual(parsed["recent_changes"], ["July 2026: Updated endpoints."])
        row = parsed["endpoint_rows"][0]
        self.assertEqual(row["host"], "*.example.com")
        self.assertEqual(row["ports"], [443, 80])
        self.assertEqual(row["protocols"], ["TCP", "UDP"])
        self.assertEqual(row["description"], "A & B")
        self.assertEqual(
            row["links"],
            [
                {
                    "field": "Supports proxies",
                    "text": "Learn more",
                    "href": "#proxy",
                }
            ],
        )
        self.assertEqual((row["table_index"], row["row_index"]), (1, 1))

    def test_renders_traceable_domains_and_both_ip_families(self):
        manifest = updater.build_manifest(parse_fixture())
        with mock.patch.multiple(updater, MIN_ROWS=1, MIN_UNIQUE_HOSTS=1):
            domainset, ruleset = updater.render_outputs(manifest)
        self.assertEqual(domainset.count(".example.com\n"), 1)
        self.assertEqual(domainset.count(".apple.com\n"), 1)
        self.assertIn("IP-CIDR,17.0.0.0/8,no-resolve\n", ruleset)
        self.assertIn("IP-CIDR6,2403:300::/32,no-resolve\n", ruleset)
        self.assertIn("IP-CIDR6,2620:149::/32,no-resolve\n", ruleset)

    def test_manifest_and_outputs_are_deterministic(self):
        manifest = updater.build_manifest(parse_fixture())
        with mock.patch.multiple(updater, MIN_ROWS=1, MIN_UNIQUE_HOSTS=1):
            serialized = updater.serialize_manifest(manifest)
            restored = json.loads(serialized)
            self.assertEqual(serialized, updater.serialize_manifest(restored))
            self.assertEqual(
                updater.render_outputs(manifest), updater.render_outputs(restored)
            )

            tampered = copy.deepcopy(manifest)
            tampered["endpoint_rows"][0]["description"] = "changed"
            with self.assertRaises(updater.SourceDataError):
                updater.validate_manifest(tampered)

    def test_rejects_table_drift_unknown_wildcard_bad_cidr_and_truncation(self):
        cases = {
            "header": ARTICLE.replace("Supports proxies", "Proxy behavior"),
            "wildcard": ARTICLE.replace("*.Example.com.", "a.*.example.com"),
            "cidr": ARTICLE.replace("17.0.0.0/8", "17.1.2.3/8"),
            "truncated": ARTICLE.rsplit("</div>", 1)[0],
        }
        for name, html in cases.items():
            with self.subTest(name=name), self.assertRaises(updater.SourceDataError):
                parse_fixture(html)


if __name__ == "__main__":
    unittest.main()
