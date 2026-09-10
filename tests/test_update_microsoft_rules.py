from __future__ import annotations

import copy
import ipaddress
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import update_microsoft_rules as updater  # noqa: E402


def record(record_id: int, **overrides):
    value = {
        "id": record_id,
        "serviceArea": "Common",
        "serviceAreaDisplayName": "Microsoft 365 Common and Office Online",
        "urls": ["login.example.com"],
        "tcpPorts": "80,443",
        "category": "Default",
        "expressRoute": False,
        "required": True,
    }
    value.update(overrides)
    return value


def fixture_manifest():
    payloads = {
        "Worldwide": [
            record(
                1,
                urls=[
                    "LOGIN.Example.com.",
                    "*.example.com",
                    "*cdn.onenote.net",
                    "autodiscover.*.onmicrosoft.com",
                ],
                ips=["203.0.113.0/24", "2001:db8::/32"],
            )
        ],
        "China": [record(2, urls=["*.partner.microsoftonline.cn"], required=False)],
        "USGovDoD": [record(3, urls=["*.apps.mil"], ips=["198.51.100.0/24"])],
        "USGovGCCHigh": [record(4, urls=["*.apps.mil", "login.example.com"])],
    }
    versions = {instance: "2026091000" for instance in updater.INSTANCES}
    return updater.build_manifest(versions, payloads)


class MicrosoftRuleGeneratorTests(unittest.TestCase):
    def test_classifies_exact_simple_and_complex_wildcards(self):
        self.assertEqual(
            updater.classify_url("Login.Example.com."),
            ("domainset", "login.example.com"),
        )
        self.assertEqual(
            updater.classify_url("*.Example.com"),
            ("domainset", ".example.com"),
        )
        self.assertEqual(
            updater.classify_url("autodiscover.*.onmicrosoft.com"),
            ("wildcard", "autodiscover.*.onmicrosoft.com"),
        )
        self.assertEqual(
            updater.classify_url("*cdn.onenote.net"),
            ("wildcard", "*cdn.onenote.net"),
        )

    def test_rejects_urls_and_unknown_wildcard_syntax(self):
        for value in ("https://example.com", "example.com/path", "cdn?.example.com", "a**b.example"):
            with self.subTest(value=value), self.assertRaises(updater.SourceDataError):
                updater.classify_url(value)

    def test_renders_all_instances_optional_records_and_both_ip_families(self):
        domainset, ruleset = updater.render_outputs(fixture_manifest())
        self.assertIn("login.example.com\n", domainset)
        self.assertIn(".example.com\n", domainset)
        self.assertIn(".partner.microsoftonline.cn\n", domainset)
        self.assertEqual(domainset.count(".apps.mil\n"), 1)
        self.assertIn("DOMAIN-WILDCARD,*cdn.onenote.net\n", ruleset)
        self.assertIn("DOMAIN-WILDCARD,autodiscover.*.onmicrosoft.com\n", ruleset)
        self.assertIn("IP-CIDR,203.0.113.0/24,no-resolve\n", ruleset)
        self.assertIn("IP-CIDR6,2001:db8::/32,no-resolve\n", ruleset)

    def test_serialization_and_rendering_are_deterministic(self):
        manifest = fixture_manifest()
        reversed_manifest = copy.deepcopy(manifest)
        reversed_manifest["instances"]["Worldwide"]["records"][0]["urls"].reverse()
        normalized = updater.validate_manifest(reversed_manifest)
        self.assertEqual(updater.render_outputs(manifest), updater.render_outputs(normalized))
        self.assertEqual(
            updater.serialize_manifest(manifest),
            updater.serialize_manifest(json.loads(updater.serialize_manifest(manifest))),
        )

    def test_rejects_schema_drift_empty_instance_and_bad_cidr(self):
        payloads = {instance: [record(index + 1)] for index, instance in enumerate(updater.INSTANCES)}
        versions = {instance: "2026091000" for instance in updater.INSTANCES}

        bad_schema = copy.deepcopy(payloads)
        bad_schema["Worldwide"][0]["newField"] = "unexpected"
        with self.assertRaises(updater.SourceDataError):
            updater.build_manifest(versions, bad_schema)

        empty = copy.deepcopy(payloads)
        empty["China"] = []
        with self.assertRaises(updater.SourceDataError):
            updater.build_manifest(versions, empty)

        bad_cidr = copy.deepcopy(payloads)
        bad_cidr["USGovDoD"][0]["ips"] = ["203.0.113.7/24"]
        with self.assertRaises(updater.SourceDataError):
            updater.render_outputs(updater.build_manifest(versions, bad_cidr))

    def test_ip_sort_order_is_numeric(self):
        manifest = fixture_manifest()
        manifest["instances"]["Worldwide"]["records"][0]["ips"] = [
            "192.0.2.0/24",
            "10.0.0.0/8",
        ]
        _, ruleset = updater.render_outputs(manifest)
        self.assertLess(
            ruleset.index("IP-CIDR,10.0.0.0/8"),
            ruleset.index("IP-CIDR,192.0.2.0/24"),
        )


if __name__ == "__main__":
    unittest.main()
