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


def power_apps_markdown():
    rows = [
        r"| *.events.data.microsoft.com | https | Telemetry |",
        r"| *.powerapps.com | https | Power Apps service |",
        r"| api.bap.microsoft.com<br>\*.api.bap.microsoft.com | https | Environment management |",
        r"| arc.msn.com<br>arc-emea.msn.com | https | In-app campaigns |",
        (
            "| http://*.crm#.dynamics.com and https://*.crm#.dynamics.com | https | "
            "<ul><li>North America: no number</li><li>Europe: 4</li>"
            "<li>Asia Pacific: 5</li></ul> |"
        ),
        r"| localhost<br>127.0.0.1 | http | Local desktop loopback |",
    ]
    rows.extend(
        f"| fixture{index}.powerapps.example | https | Fixture endpoint {index} |"
        for index in range(1, 20)
    )
    return "\n".join(
        [
            "---",
            "ms.date: 09/10/2026",
            "---",
            "## Required services",
            "",
            "| Domains | Protocols | Uses |",
            "| --- | --- | --- |",
            *rows,
            "",
            "## Deprecated endpoints",
        ]
    )


def fixture_power_apps_source():
    return updater.build_power_apps_source(power_apps_markdown())


def fixture_supplemental_sources():
    sources = {}
    for name, spec in updater.SUPPLEMENTAL_SOURCES.items():
        patterns = sorted(spec["required"])
        while len(patterns) < spec["min_domains"]:
            patterns.append(f"fixture{len(patterns)}.{name.replace('_', '-')}.example.com")
        records = [
            {"source": pattern, "normalized_domains": [pattern]}
            for pattern in patterns
        ]
        sources[name] = updater._source_block(spec, "09/10/2026", records)
    return sources


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
    return updater.build_manifest(
        versions,
        payloads,
        fixture_power_apps_source(),
        fixture_supplemental_sources(),
    )


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
        self.assertIn("arc.msn.com\n", domainset)
        self.assertIn(".crm.dynamics.com\n", domainset)
        self.assertIn(".crm4.dynamics.com\n", domainset)
        self.assertIn(".crm5.dynamics.com\n", domainset)
        self.assertIn("marketplace.visualstudio.com\n", domainset)
        self.assertIn(".windowsupdate.com\n", domainset)
        self.assertIn("time.windows.com\n", domainset)
        self.assertNotIn("localhost", domainset)
        self.assertNotIn("127.0.0.1", ruleset)

    def test_parses_power_apps_table_and_preserves_source_metadata(self):
        source = fixture_power_apps_source()
        self.assertEqual(source["document_date"], "09/10/2026")
        self.assertEqual(source["excluded_local_targets"], ["127.0.0.1", "localhost"])
        self.assertRegex(source["semantic_hash"], r"^[0-9a-f]{64}$")
        published = {
            domain
            for record_value in source["records"]
            for domain in record_value["normalized_domains"]
        }
        self.assertIn("arc.msn.com", published)
        self.assertIn("*.crm.dynamics.com", published)
        self.assertIn("*.crm4.dynamics.com", published)
        self.assertIn("*.crm5.dynamics.com", published)
        self.assertEqual(
            source["semantic_hash"],
            fixture_power_apps_source()["semantic_hash"],
        )

    def test_rejects_power_apps_structure_drift_and_unknown_url_template(self):
        with self.assertRaises(updater.SourceDataError):
            updater.build_power_apps_source(
                power_apps_markdown().replace("| Domains | Protocols | Uses |", "| Host | Protocol | Use |")
            )
        with self.assertRaises(updater.SourceDataError):
            updater.build_power_apps_source(
                power_apps_markdown().replace("arc.msn.com", "https://arc.msn.com")
            )

    def test_parses_all_supplemental_source_shapes(self):
        vscode_spec = updater.SUPPLEMENTAL_SOURCES["vscode"]
        vscode_domains = sorted(vscode_spec["required"])
        while len(vscode_domains) < vscode_spec["min_domains"]:
            vscode_domains.append(f"fixture{len(vscode_domains)}.vscode.example.com")
        vscode = "---\nms.date: 09/10/2026\n---\n## Common hostnames\n" + "\n".join(
            f"- `{domain}` - {{% data variables.product.prodname_vscode %}} fixture"
            for domain in vscode_domains
        ) + "\n## Proxy server support\n"
        parsed_vscode = {
            value
            for record_value in updater.build_supplemental_source("vscode", vscode)["records"]
            for value in record_value["normalized_domains"]
        }
        self.assertIn("marketplace.visualstudio.com", parsed_vscode)
        self.assertNotIn("variables.product.prodname", parsed_vscode)

        for name in ("windows_enterprise", "windows_non_enterprise"):
            spec = updater.SUPPLEMENTAL_SOURCES[name]
            domains = sorted(spec["required"])
            while len(domains) < spec["min_domains"]:
                domains.append(f"fixture{len(domains)}.{name.replace('_', '-')}.example.com")
            markdown = "---\nms.date: 09/10/2026\n---\n| Area | Destination |\n| --- | --- |\n" + "\n".join(
                f"| Area | {domain} |" for domain in domains
            )
            source = updater.build_supplemental_source(name, markdown)
            self.assertGreaterEqual(len(source["records"]), spec["min_domains"])

        ncsi = "---\nms.date: 09/10/2026\n---\n## More information\n" + "\n".join(
            [
                "`www.msftncsi.com`",
                "`dns.msftncsi.com`",
                "`*.msftncsi.com`",
                "`*.msftconnecttest.com`",
                "- Windows 8.1 or earlier versions:",
                "See [proxy guidance](use-authenticated-proxy-servers.md).",
            ]
        ) + "\n## Workaround\n"
        self.assertEqual(
            len(updater.build_supplemental_source("ncsi", ncsi)["records"]),
            4,
        )

        time_source = "---\nms.date: 09/10/2026\n---\n| NtpServer | `time.windows.com`, 0x9 |\n"
        self.assertEqual(
            updater.build_supplemental_source("windows_time", time_source)["records"][0]["normalized_domains"],
            ["time.windows.com"],
        )

        whiteboard = '---\nms.date: 09/10/2026\n---\n* Add Whiteboard.ms, \\*.whiteboard.microsoft.com, and wbd.ms to your list of allowed sites.'
        self.assertEqual(
            updater.build_supplemental_source("whiteboard", whiteboard)["records"][0]["normalized_domains"],
            ["*.whiteboard.microsoft.com", "wbd.ms", "whiteboard.ms"],
        )

    def test_markdown_wildcards_footnotes_and_joined_hosts_are_normalized(self):
        self.assertEqual(
            updater._extract_host_patterns(
                r"watson.\*.microsoft.com arc.msn.com\*ris.api.iris.microsoft.com "
                r"wdcp.microsoft.comwdcpalt.microsoft.com login.live.com\*"
            ),
            [
                "arc.msn.com",
                "login.live.com",
                "ris.api.iris.microsoft.com",
                "watson.*.microsoft.com",
                "wdcp.microsoft.com",
                "wdcpalt.microsoft.com",
            ],
        )

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
            updater.build_manifest(
                versions, bad_schema, fixture_power_apps_source(), fixture_supplemental_sources()
            )

        empty = copy.deepcopy(payloads)
        empty["China"] = []
        with self.assertRaises(updater.SourceDataError):
            updater.build_manifest(
                versions, empty, fixture_power_apps_source(), fixture_supplemental_sources()
            )

        bad_cidr = copy.deepcopy(payloads)
        bad_cidr["USGovDoD"][0]["ips"] = ["203.0.113.7/24"]
        with self.assertRaises(updater.SourceDataError):
            updater.render_outputs(
                updater.build_manifest(
                    versions,
                    bad_cidr,
                    fixture_power_apps_source(),
                    fixture_supplemental_sources(),
                )
            )

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
