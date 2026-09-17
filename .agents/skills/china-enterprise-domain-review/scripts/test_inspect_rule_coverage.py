from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("inspect_rule_coverage.py")
SPEC = importlib.util.spec_from_file_location("inspect_rule_coverage", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class InspectRuleCoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        dist = self.repo / "dist"
        dist.mkdir()
        (dist / "china_enterprise_domainset.txt").write_text(
            "# core\n.example.cn\nexact.example.com\n", encoding="utf-8"
        )
        (dist / "china_enterprise_manual_ruleset.txt").write_text(
            "# manual\nDOMAIN,api.manual.cn\nDOMAIN-SUFFIX,legacy.cn\n", encoding="utf-8"
        )
        (dist / "proxy_targets_ruleset.txt").write_text(
            "DOMAIN-WILDCARD,*.proxy.example\n", encoding="utf-8"
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_normalizes_idna_and_rejects_non_domains(self):
        self.assertEqual(MODULE.normalize_domain("例子.公司.cn."), "xn--fsqu00a.xn--55qx5d.cn")
        for value in ("https://example.com", "1.1.1.1", "*.example.com", "a b.com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                MODULE.normalize_domain(value)

    def test_reports_core_manual_and_other_coverage(self):
        core = MODULE.inspect_domain(self.repo, "sub.example.cn")
        manual = MODULE.inspect_domain(self.repo, "api.manual.cn")
        other = MODULE.inspect_domain(self.repo, "a.proxy.example")
        missing = MODULE.inspect_domain(self.repo, "missing.example")
        self.assertEqual(core["current_classification"], "core-domainset")
        self.assertEqual(manual["current_classification"], "enterprise-manual")
        self.assertEqual(other["current_classification"], "covered-elsewhere")
        self.assertEqual(missing["current_classification"], "unclassified")

    def test_core_takes_precedence_but_all_matches_are_reported(self):
        (self.repo / "dist" / "china_enterprise_manual_ruleset.txt").write_text(
            "DOMAIN,sub.example.cn\n", encoding="utf-8"
        )
        result = MODULE.inspect_domain(self.repo, "sub.example.cn")
        self.assertEqual(result["current_classification"], "core-domainset")
        self.assertEqual(len(result["matches"]), 2)


if __name__ == "__main__":
    unittest.main()
