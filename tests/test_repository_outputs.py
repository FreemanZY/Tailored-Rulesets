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
            "URL-REGEX",
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

    def test_wechat_mmtls_direct_rule_is_narrow(self):
        rules = active_lines(ROOT / "dist" / "force_direct_ruleset.txt")
        self.assertEqual(len(rules), 1)
        rule_type, pattern = rules[0].split(",", 1)
        self.assertEqual(rule_type, "URL-REGEX")
        regex = re.compile(pattern)
        self.assertIsNotNone(regex.search("http://203.205.151.204/mmtls/5eac4f54"))
        self.assertIsNotNone(regex.search("http://203.205.151.204:80/mmtls/00000dd9?x=1"))
        self.assertIsNone(regex.search("https://203.205.151.204/mmtls/5eac4f54"))
        self.assertIsNone(regex.search("http://extshort.weixin.qq.com/mmtls/5eac4f54"))
        self.assertIsNone(regex.search("http://999.999.999.999/mmtls/5eac4f54"))
        self.assertIsNone(regex.search("http://203.205.151.204/other/5eac4f54"))
        self.assertIsNone(regex.search("http://203.205.151.204/mmtls/5eac4f5"))

    def test_china_enterprise_domains_and_asns_are_scoped(self):
        domains = active_lines(ROOT / "dist" / "china_enterprise_domainset.txt")
        self.assertEqual(
            set(domains),
            {
                ".1688.com", ".alibaba.com", ".alibabacloud.com", ".alicdn.com",
                ".aliexpress.com", ".alipay.com", ".alipayobjects.com", ".aliyun.com",
                ".aliyuncs.com", ".amap.com", ".autonavi.com", ".cainiao.com",
                ".dingtalk.com", ".taobao.com", ".tbcdn.cn", ".tmall.com",
                ".ykimg.com", ".youku.com", ".1mall.com", ".360buy.cn",
                ".360buy.com", ".360buy.com.cn", ".360buyimg.com", ".7fresh.com",
                ".baitiao.com", ".chinabank.com.cn", ".healthjd.com", ".jcloud.com",
                ".jcloudcs.com", ".jd.com", ".jd.hk", ".jdcloud.com", ".jclps.com",
                ".jdpay.com", ".jdwl.com", ".wangyin.com", ".yhd.com",
                ".yihaodian.com", ".yiyaojd.com", ".dnspod.cn", ".dnspod.com",
                ".gtimg.com", ".myqcloud.com", ".qcloud.com", ".qpic.cn", ".qq.com",
                ".qqmail.com", ".tencent-cloud.com", ".tencent.com",
                ".tencentcloud.com", ".tencentcloudapi.com", ".tenpay.com",
                ".wechat.com", ".wechatpay.com", ".weixinbridge.com", ".weiyun.com",
            },
        )
        self.assertTrue(all(domain.startswith(".") for domain in domains))
        self.assertEqual(
            active_lines(ROOT / "dist" / "china_enterprise_asn_ruleset.txt"),
            ["IP-ASN,24429", "IP-ASN,37963", "IP-ASN,45102", "IP-ASN,131486", "IP-ASN,137753", "IP-ASN,45090", "IP-ASN,132203"],
        )

    def test_china_carrier_asns_are_domestic_backbones_only(self):
        self.assertEqual(
            active_lines(ROOT / "dist" / "china_carrier_asn_ruleset.txt"),
            ["IP-ASN,4134", "IP-ASN,4809", "IP-ASN,4837", "IP-ASN,9929", "IP-ASN,9808"],
        )


if __name__ == "__main__":
    unittest.main()
