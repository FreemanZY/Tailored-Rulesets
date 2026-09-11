from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import update_google_rules as updater  # noqa: E402


def html_fixture(title: str, url: str, body: str, framework: str = "devsite") -> str:
    css = "devsite-article-body" if framework == "devsite" else "article-content-container"
    return f"""<!doctype html><html><head><link rel="canonical" href="{url}"></head>
    <body><h1>{title}</h1><div class="{css}">{body}</div></body></html>"""


def relaxed_specs():
    specs = copy.deepcopy(updater.PAGE_SPECS)
    for spec in specs.values():
        spec["min_hosts"] = 0
        spec["min_ips"] = 0
    return specs


def prefix_payload(token: str, prefixes: list[dict[str, str]]):
    return {"syncToken": token, "creationTime": "2026-09-10T00:00:00Z", "prefixes": prefixes}


def fixture_manifest():
    pages = []
    for page_id, spec in relaxed_specs().items():
        records = []
        if page_id == "workspace":
            records = [
                {"type": "host", "section": ["Required"], "optional": False, "raw": "https://Login.Example.com/path", "source": "https://Login.Example.com/path", "host": "login.example.com", "path": "/path", "port": None, "protocol": None},
                {"type": "host", "section": ["Required"], "optional": False, "raw": "*.Example.com", "source": "*.Example.com", "host": "*.example.com", "path": None, "port": None, "protocol": None},
                {"type": "host", "section": ["Required"], "optional": False, "raw": "alt*.gstatic.com", "source": "alt*.gstatic.com", "host": "alt*.gstatic.com", "path": None, "port": None, "protocol": None},
                {"type": "host", "section": ["Required"], "optional": False, "raw": "accounts.google.[country]", "source": "accounts.google.[country]", "host": "accounts.google.[country]", "path": None, "port": None, "protocol": None},
            ]
        if page_id == "meet":
            records = [
                {"type": "ip", "section": ["Step 3"], "optional": False, "raw": "192.0.2.0/25", "cidr": "192.0.2.0/25"},
                {"type": "ip", "section": ["Step 3"], "optional": False, "raw": "2001:db8:1::/48", "cidr": "2001:db8:1::/48"},
            ]
        pages.append({"id": page_id, "url": spec["url"], "canonical_url": spec["url"].rstrip("/"), "title": spec["title"], "last_updated": None, "records": records})
    goog = updater.normalize_prefix_payload("goog", prefix_payload("1", [{"ipv4Prefix": "192.0.2.0/24"}, {"ipv6Prefix": "2001:db8::/32"}]))
    cloud = updater.normalize_prefix_payload("cloud", prefix_payload("1", [{"ipv4Prefix": "192.0.2.128/25", "service": "Google Cloud", "scope": "test"}, {"ipv6Prefix": "2001:db8:8000::/33", "service": "Google Cloud", "scope": "test"}]))
    manifest = {"schema_version": 1, "pages": pages, "ip_sources": {"goog": goog, "cloud": cloud}, "default_ranges": updater.derive_default_ranges(goog, cloud), "semantic_sha256": ""}
    manifest["semantic_sha256"] = updater._semantic_hash(manifest)
    return manifest


class GoogleRuleGeneratorTests(unittest.TestCase):
    def test_all_six_fixed_page_contracts_and_both_frameworks(self):
        for page_id, original in relaxed_specs().items():
            with self.subTest(page_id=page_id):
                spec = copy.deepcopy(original)
                if page_id == "ip_ranges":
                    body = f'<a href="{updater.GOOG_JSON_URL}">goog</a><a href="{updater.CLOUD_JSON_URL}">cloud</a>'
                elif page_id == "chrome":
                    body = "<h2>Hostname allowlist for all ChromeOS and Chrome Enterprise Core devices</h2><p>chrome.example.com</p>"
                elif page_id == "meet":
                    body = "<h4>Step 2: URIs</h4><p>meet.example.com</p><h4>Step 3: IPs</h4><p>192.0.2.0/24</p>"
                else:
                    body = "<h2>Required hosts</h2><p>service.example.com</p>"
                html = html_fixture(spec["title"], spec["url"], body, spec["framework"])
                with mock.patch.dict(updater.PAGE_SPECS, {page_id: spec}, clear=True):
                    page = updater.parse_page_html(page_id, html)
                self.assertEqual(page["id"], page_id)
                if page_id == "ip_ranges":
                    self.assertEqual(page["records"], [])
                else:
                    self.assertTrue(page["records"])

    def test_classifies_exact_standard_complex_country_and_numeric_patterns(self):
        self.assertEqual(updater.classify_host("Login.Example.com."), [("domainset", "login.example.com")])
        self.assertEqual(updater.classify_host("*.Example.com"), [("domainset", ".example.com")])
        self.assertEqual(updater.classify_host("alt*.gstatic.com"), [("wildcard", "alt*.gstatic.com")])
        self.assertEqual(updater.classify_host("accounts.google.[country]"), [("wildcard", "accounts.google.*")])
        self.assertEqual(updater.classify_host("lh[0-9].google.com"), [("domainset", f"lh{x}.google.com") for x in "0123456789"])
        self.assertEqual(updater.classify_host("*.clients[0–9].google.com")[0], ("domainset", ".clients0.google.com"))

    def test_rejects_unknown_templates_and_invalid_hosts(self):
        for value in ("foo.[region].google.com", "a[0-9]b[0-9].google.com", "a**b.google.com", "bad_name.google.com"):
            with self.subTest(value=value), self.assertRaises(updater.SourceDataError):
                updater.classify_host(value)

    def test_parses_devsite_url_path_port_protocol_and_ip(self):
        spec = copy.deepcopy(updater.PAGE_SPECS["meet"])
        spec.update(min_hosts=1, min_ips=1)
        body = "<h4>Step 2: URIs</h4><p>https://Meet.Example.com/path</p><h4>Step 3: IPs</h4><li>media.example.com:443/HTTPS 192.0.2.0/24</li><h4>Step 4: Capacity</h4><p>2.4-GHz</p>"
        html = html_fixture(spec["title"], spec["url"], body)
        with mock.patch.dict(updater.PAGE_SPECS, {"meet": spec}):
            page = updater.parse_page_html("meet", html)
        hosts = [x for x in page["records"] if x["type"] == "host"]
        self.assertEqual({x["host"] for x in hosts}, {"meet.example.com", "media.example.com"})
        self.assertEqual(next(x for x in hosts if x["host"] == "meet.example.com")["path"], "/path")
        self.assertIn("192.0.2.0/24", [x["cidr"] for x in page["records"] if x["type"] == "ip"])

    def test_parses_chrome_current_sections_and_ignores_updates_and_footnotes(self):
        spec = copy.deepcopy(updater.PAGE_SPECS["chrome"])
        spec.update(min_hosts=2, min_ips=0)
        body = "<h2>Updates to the hostname allowlist</h2><li>removed.example.com</li><h2>Hostname allowlist for all ChromeOS and Chrome Enterprise Core devices</h2><p>*.1e100.net<sup>1</sup> accounts.google.[country]</p><p><sup>1</sup> For more information, see What is 1e100.net?</p><h2>Was this helpful?</h2>"
        html = html_fixture(spec["title"], spec["url"] + "?hl=en", body, "chrome")
        with mock.patch.dict(updater.PAGE_SPECS, {"chrome": spec}):
            page = updater.parse_page_html("chrome", html)
        self.assertEqual({x["host"] for x in page["records"]}, {"*.1e100.net", "accounts.google.[country]"})

    def test_cidr_subtraction_handles_partial_equal_and_both_families(self):
        goog = updater.normalize_prefix_payload("goog", prefix_payload("7", [{"ipv4Prefix": "192.0.2.0/24"}, {"ipv4Prefix": "198.51.100.0/24"}, {"ipv6Prefix": "2001:db8::/32"}]))
        cloud = updater.normalize_prefix_payload("cloud", prefix_payload("7", [{"ipv4Prefix": "192.0.2.128/25", "service": "Google Cloud", "scope": "x"}, {"ipv4Prefix": "198.51.100.0/24", "service": "Google Cloud", "scope": "x"}, {"ipv6Prefix": "2001:db8:8000::/33", "service": "Google Cloud", "scope": "x"}]))
        self.assertEqual(updater.derive_default_ranges(goog, cloud), ["192.0.2.0/25", "2001:db8::/33"])
        cloud["sync_token"] = "8"
        with self.assertRaises(updater.SourceDataError):
            updater.derive_default_ranges(goog, cloud)

    def test_cidr_subtraction_does_not_merge_adjacent_official_records(self):
        goog = updater.normalize_prefix_payload("goog", prefix_payload("9", [
            {"ipv4Prefix": "192.0.2.0/25"},
            {"ipv4Prefix": "192.0.2.128/25"},
            {"ipv6Prefix": "2001:db8::/33"},
            {"ipv6Prefix": "2001:db8:8000::/33"},
        ]))
        cloud = updater.normalize_prefix_payload("cloud", prefix_payload("9", [
            {"ipv4Prefix": "198.51.100.0/24", "service": "Google Cloud", "scope": "test"},
            {"ipv6Prefix": "2001:db9::/32", "service": "Google Cloud", "scope": "test"},
        ]))
        self.assertEqual(updater.derive_default_ranges(goog, cloud), [
            "192.0.2.0/25", "192.0.2.128/25", "2001:db8::/33", "2001:db8:8000::/33"
        ])

    def test_rendering_and_serialization_are_deterministic(self):
        with mock.patch.dict(updater.PAGE_SPECS, relaxed_specs(), clear=True):
            manifest = updater.validate_manifest(fixture_manifest())
            domainset, ruleset = updater.render_outputs(manifest)
            self.assertIn("login.example.com\n", domainset)
            self.assertIn(".example.com\n", domainset)
            self.assertIn("DOMAIN-WILDCARD,accounts.google.*\n", ruleset)
            self.assertIn("DOMAIN-WILDCARD,alt*.gstatic.com\n", ruleset)
            self.assertIn("IP-CIDR,192.0.2.0/25,no-resolve\n", ruleset)
            self.assertIn("IP-CIDR6,2001:db8::/33,no-resolve\n", ruleset)
            serialized = updater.serialize_manifest(manifest)
            self.assertEqual(serialized, updater.serialize_manifest(json.loads(serialized)))

    def test_manifest_hash_detects_tampering(self):
        manifest = fixture_manifest()
        manifest["default_ranges"][0] = "192.0.2.0/26"
        with mock.patch.dict(updater.PAGE_SPECS, relaxed_specs(), clear=True), self.assertRaises(updater.SourceDataError):
            updater.validate_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
