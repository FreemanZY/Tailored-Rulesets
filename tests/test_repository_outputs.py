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


def legacy_domain_entries_from_rules(path: Path):
    entries = []
    for line in active_lines(path):
        rule_type, value, *_ = line.split(",")
        if rule_type == "DOMAIN":
            entries.append(value)
        elif rule_type == "DOMAIN-SUFFIX":
            entries.append(f".{value}")
        else:
            raise AssertionError(f"unexpected non-domain rule in {path.name}: {line}")
    return entries


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
        lines = legacy_domain_entries_from_rules(ROOT / "dist" / "google_manual_ruleset.txt")
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
        rules = active_lines(ROOT / "dist" / "china_enterprise_manual_ruleset.txt")
        url_rules = [rule for rule in rules if rule.startswith("URL-REGEX,")]
        self.assertEqual(len(url_rules), 1)
        rule_type, pattern = url_rules[0].split(",", 1)
        self.assertEqual(rule_type, "URL-REGEX")
        regex = re.compile(pattern)
        self.assertIsNotNone(regex.search("http://203.205.151.204/mmtls/5eac4f54"))
        self.assertIsNotNone(regex.search("http://203.205.151.204:80/mmtls/00000dd9?x=1"))
        self.assertIsNone(regex.search("https://203.205.151.204/mmtls/5eac4f54"))
        self.assertIsNone(regex.search("http://extshort.weixin.qq.com/mmtls/5eac4f54"))
        self.assertIsNone(regex.search("http://999.999.999.999/mmtls/5eac4f54"))
        self.assertIsNone(regex.search("http://203.205.151.204/other/5eac4f54"))
        self.assertIsNone(regex.search("http://203.205.151.204/mmtls/5eac4f5"))

    def test_legacy_manual_import_is_scoped_and_conflicts_are_resolved(self):
        enterprise_manual = active_lines(ROOT / "dist" / "china_enterprise_manual_ruleset.txt")
        force_direct = active_lines(ROOT / "dist" / "force_direct_ruleset.txt")
        rejected = active_lines(ROOT / "dist" / "reject_ruleset.txt")
        self.assertEqual((len(enterprise_manual), len(force_direct), len(rejected)), (94, 15, 62))
        self.assertEqual(len(force_direct), len(set(force_direct)))
        self.assertEqual(len(rejected), len(set(rejected)))
        for domain in {"h-adashx.ut.fliggy.com", "interface-log.gaiaworkforce.com", "mdap.alipay.com"}:
            self.assertIn(f"DOMAIN,{domain}", rejected)
            self.assertNotIn(f"DOMAIN,{domain}", force_direct)
        self.assertNotIn("DOMAIN-SUFFIX,h-adashx.ut.fliggy.com", enterprise_manual)
        for migrated in {
            "DOMAIN,api-unionid.meituan.com",
            "DOMAIN,api.mijia.tech",
            "DOMAIN,api.udache.com",
            "DOMAIN,appgw.huazhu.com",
            "DOMAIN,mobile.12306.cn",
            "DOMAIN,gator.volces.com",
            "DOMAIN-SUFFIX,cmbwinglungbank.com",
            "DOMAIN-SUFFIX,rcs01.5gm.wo.cn",
        }:
            self.assertIn(migrated, enterprise_manual)
            self.assertNotIn(migrated, force_direct)
        published = "\n".join(force_direct + enterprise_manual)
        self.assertNotIn("savc-rt.com", published)
        for stale_ip in {"183.134.53.177", "118.212.236.23", "118.212.235.156", "118.212.235.76"}:
            self.assertNotIn(stale_ip, published)

    def test_manual_categories_use_one_grouped_ruleset(self):
        retired = {
            "ai_domainset.txt", "apple_manual_domainset.txt", "china_domainset.txt",
            "china_enterprise_manual_domainset.txt", "force_direct_domainset.txt",
            "google_manual_domainset.txt", "high_traffic_domainset.txt",
            "lan_domainset.txt", "lan_ip_ruleset.txt", "local_dns_domainset.txt",
            "microsoft_manual_domainset.txt", "proxy_targets_domainset.txt",
            "reject_domainset.txt", "wechat_manual_domainset.txt",
            "wechat_manual_ruleset.txt",
        }
        self.assertFalse(any((ROOT / "dist" / name).exists() for name in retired))
        manual_rulesets = {
            "ai_manual_ruleset.txt", "apple_manual_ruleset.txt",
            "china_enterprise_manual_ruleset.txt", "china_manual_ruleset.txt",
            "force_direct_ruleset.txt", "google_manual_ruleset.txt",
            "high_traffic_ruleset.txt", "lan_ruleset.txt", "local_dns_ruleset.txt",
            "microsoft_manual_ruleset.txt", "proxy_targets_ruleset.txt",
            "reject_ruleset.txt",
        }
        for name in manual_rulesets:
            with self.subTest(name=name):
                text = (ROOT / "dist" / name).read_text(encoding="utf-8-sig")
                self.assertIn("# Group:", text)
        self.assertEqual(len(active_lines(ROOT / "dist" / "high_traffic_ruleset.txt")), 18)
        self.assertEqual(len(active_lines(ROOT / "dist" / "proxy_targets_ruleset.txt")), 7)
        self.assertEqual(len(active_lines(ROOT / "dist" / "lan_ruleset.txt")), 9)

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
            ["IP-ASN,24429", "IP-ASN,37963", "IP-ASN,45102", "IP-ASN,131486", "IP-ASN,137753", "IP-ASN,45090", "IP-ASN,132203", "IP-ASN,55990", "IP-ASN,131516", "IP-ASN,17428"],
        )

    def test_china_carrier_asns_are_selected_operator_networks(self):
        self.assertEqual(
            active_lines(ROOT / "dist" / "china_carrier_asn_ruleset.txt"),
            ["IP-ASN,4134", "IP-ASN,4809", "IP-ASN,4812", "IP-ASN,4837", "IP-ASN,9929", "IP-ASN,17621", "IP-ASN,9808", "IP-ASN,139887", "IP-ASN,134756", "IP-ASN,140717"],
        )


if __name__ == "__main__":
    unittest.main()
