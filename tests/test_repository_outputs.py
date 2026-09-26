from __future__ import annotations

import ipaddress
import hashlib
import fnmatch
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


def generated_domain_coverage(vendor: str, rule: str):
    domainset = active_lines(ROOT / "dist" / f"{vendor}_generated_domainset.txt")
    ruleset_name = (
        "apple_generated_ip_ruleset.txt"
        if vendor == "apple"
        else f"{vendor}_generated_ruleset.txt"
    )
    ruleset = active_lines(ROOT / "dist" / ruleset_name)
    exact = {entry for entry in domainset if not entry.startswith(".")}
    suffixes = {entry[1:] for entry in domainset if entry.startswith(".")}
    wildcards = {
        entry.split(",", 1)[1]
        for entry in ruleset
        if entry.startswith("DOMAIN-WILDCARD,")
    }
    rule_type, value = rule.split(",", 1)
    if rule_type == "DOMAIN":
        return (
            value in exact
            or any(value == suffix or value.endswith(f".{suffix}") for suffix in suffixes)
            or any(fnmatch.fnmatchcase(value, wildcard) for wildcard in wildcards)
        )
    if rule_type == "DOMAIN-SUFFIX":
        return any(value == suffix or value.endswith(f".{suffix}") for suffix in suffixes)
    raise AssertionError(f"unexpected manual domain rule: {rule}")


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
        microsoft_generated_domains = active_lines(
            ROOT / "dist" / "microsoft_generated_domainset.txt"
        )
        microsoft_manual_rules = active_lines(ROOT / "dist" / "microsoft_manual_ruleset.txt")
        self.assertIn("arc.msn.com", microsoft_generated_domains)
        self.assertNotIn("DOMAIN,arc.msn.com", microsoft_manual_rules)
        self.assertEqual(
            set(microsoft_manual_rules),
            {
                "DOMAIN,apac01.azure-devices.net",
                "DOMAIN,kbmvdg.dm.files.1drv.com",
                "DOMAIN,icmgzq.by.files.1drv.com",
                "DOMAIN,my.microsoftpersonalcontent.com",
                "DOMAIN,in.appcenter.ms",
                "DOMAIN,ax-ring.msedge.net",
                "DOMAIN,lamr-staging-t-tunicast.msedge.net",
                "DOMAIN,teams.nelgallatin.measure.office365.cn",
                "DOMAIN,s.cn.bing.net",
                "DOMAIN,s1.tc.bing.net",
            },
        )
        for migrated in {
            "DOMAIN,default.exp-tas.com",
            "DOMAIN,img-s-msn-com.akamaized.net",
            "DOMAIN,ipv6.msftncsi.com",
            "DOMAIN,api.msn.com",
            "DOMAIN-SUFFIX,download.windowsupdate.com",
            "DOMAIN,fp.msedge.net",
            "DOMAIN,marketplace.visualstudio.com",
            "DOMAIN,ntp.msn.com",
            "DOMAIN,time.windows.com",
            "DOMAIN,update.code.visualstudio.com",
            "DOMAIN,vscode-sync.trafficmanager.net",
            "DOMAIN,wbd.ms",
            "DOMAIN,whiteboard.ms",
            "DOMAIN,windows.msn.com",
            "DOMAIN,www.msftncsi.com",
            "DOMAIN-SUFFIX,gallery.vsassets.io",
            "DOMAIN-SUFFIX,gallerycdn.vsassets.io",
            "DOMAIN-SUFFIX,vscode-cdn.net",
        }:
            self.assertTrue(generated_domain_coverage("microsoft", migrated), migrated)

    def test_legacy_google_ip_filename_is_removed(self):
        self.assertFalse((ROOT / "dist" / "google_generated_ip_ruleset.txt").exists())

    def test_uncovered_legacy_google_domains_remain_manual(self):
        lines = legacy_domain_entries_from_rules(ROOT / "dist" / "google_manual_ruleset.txt")
        payload = ("\n".join(lines) + "\n").encode()
        self.assertEqual(len(lines), 414)
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            "03530fc4c643e0601ad96ac9f04c39fbc9281454f0d033820c4c08d9a12faf73",
        )

    def test_vendor_manual_rules_do_not_duplicate_or_broaden_generated_rules(self):
        for vendor in ("apple", "microsoft", "google"):
            manual = active_lines(ROOT / "dist" / f"{vendor}_manual_ruleset.txt")
            generated_exact = {
                entry
                for entry in active_lines(ROOT / "dist" / f"{vendor}_generated_domainset.txt")
                if not entry.startswith(".")
            }
            for rule in manual:
                with self.subTest(vendor=vendor, rule=rule):
                    self.assertFalse(generated_domain_coverage(vendor, rule))
                    rule_type, value = rule.split(",", 1)
                    if rule_type == "DOMAIN-SUFFIX":
                        self.assertNotIn(value, generated_exact)

        apple_manual = active_lines(ROOT / "dist" / "apple_manual_ruleset.txt")
        self.assertIn("DOMAIN-SUFFIX,apple.com.akadns.net", apple_manual)
        self.assertIn("DOMAIN-SUFFIX,apple.com.edgekey.net", apple_manual)
        self.assertNotIn("DOMAIN-SUFFIX,com.akadns.net", apple_manual)
        self.assertNotIn("DOMAIN-SUFFIX,com.edgekey.net", apple_manual)

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
        self.assertEqual((len(enterprise_manual), len(force_direct), len(rejected)), (131, 6, 63))
        self.assertEqual(len(force_direct), len(set(force_direct)))
        self.assertEqual(len(rejected), len(set(rejected)))
        for domain in {
            "h-adashx.ut.fliggy.com",
            "interface-log.gaiaworkforce.com",
            "mdap.alipay.com",
            "statistic.live.126.net",
        }:
            self.assertIn(f"DOMAIN,{domain}", rejected)
            self.assertNotIn(f"DOMAIN,{domain}", force_direct)
        self.assertNotIn("DOMAIN-SUFFIX,h-adashx.ut.fliggy.com", enterprise_manual)
        for migrated in {
            "DOMAIN,api.mijia.tech",
            "DOMAIN,gator.volces.com",
            "DOMAIN,wealthplaza.tech.citic",
            "DOMAIN,isure6-stream-qqmusic.a.bdycdn.cn",
            "DOMAIN,ap2.qiyukf.com",
            "DOMAIN,lbs.netease.im",
            "DOMAIN,prewxacode.wxqcloud.qq.com.cn",
            "DOMAIN,air-matters.com",
            "DOMAIN,data.air-matters.com",
            "DOMAIN,heatmap.air-matters.app",
            "DOMAIN,y.gtimg.cn",
            "DOMAIN,dimg10.c-ctrip.com",
            "DOMAIN,vod-license-m.volccdn.com",
            "DOMAIN-SUFFIX,xmcdn.com",
            "DOMAIN-SUFFIX,zhishidashi.com",
            "DOMAIN-SUFFIX,taobao.net",
            "DOMAIN-SUFFIX,taobaocdn.com",
            "DOMAIN-SUFFIX,taobaocdn.net",
            "DOMAIN-SUFFIX,tb.cn",
            "DOMAIN-SUFFIX,cmbwinglungbank.com",
            "DOMAIN-SUFFIX,rcs01.5gm.wo.cn",
            "DOMAIN,apm.xiaojukeji.com",
            "DOMAIN,catchdata.xiaojukeji.com",
            "DOMAIN,img-ys011.didistatic.com",
            "DOMAIN,s3-hnapuhdd-cdn.didistatic.com",
            "DOMAIN,tracker.didistatic.com",
            "DOMAIN,al-log.d.meituan.net",
            "DOMAIN,maplocatesdksnapshot.d.meituan.net",
            "DOMAIN,route-stats.d.meituan.net",
            "DOMAIN,mmec.wxqcloud.qq.com.cn",
            "DOMAIN,alilang-intranet.alibaba-inc.com",
            "DOMAIN,live-appserver-sh.alivecdn.com",
            "DOMAIN,time.edu.cn",
            "DOMAIN-SUFFIX,hrone.cn",
            "DOMAIN,bd0.d.meituan.net",
            "DOMAIN,ddfs-public.ddimg.mobi",
            "DOMAIN,device-sec.s3.cn-north-1.jdcloud-oss.com",
            "DOMAIN,mlvbdc.live.tlivesource.com",
            "DOMAIN,report-online.sh.wxgateway.com",
            "DOMAIN,trip-hisv.alibtrip.com",
            "DOMAIN,cn-afp.apitd.net",
        }:
            self.assertIn(migrated, enterprise_manual)
            self.assertNotIn(migrated, force_direct)
        for promoted in {
            "DOMAIN,api.neixin.cn",
            "DOMAIN,gateway.gaiaworkforce.com",
            "DOMAIN,ptf.flyertrip.com",
            "DOMAIN,www.chinaebill.cn",
            "DOMAIN,www.flyert.com",
            "DOMAIN,www.flyert.com.cn",
            "DOMAIN-SUFFIX,cup.com.cn",
        }:
            self.assertNotIn(promoted, force_direct)
        self.assertIn("DOMAIN,dns.alidns.com", force_direct)
        published = "\n".join(force_direct + enterprise_manual)
        for core_suffix in {
            "huazhu.com", "fliggy.com", "feizhu.com", "ele.me", "elemecdn.com",
            "meituan.com", "dianping.com", "yunpei.com", "yunxiu.com",
            "udache.com", "diditaxi.com.cn", "12306.cn", "ceair.com", "yaduo.com",
        }:
            self.assertFalse(any(core_suffix in rule for rule in enterprise_manual))
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
        proxy_targets = active_lines(ROOT / "dist" / "proxy_targets_ruleset.txt")
        self.assertEqual(len(proxy_targets), 8)
        self.assertIn("DOMAIN,api.peakwatch.co", proxy_targets)
        lan_rules = active_lines(ROOT / "dist" / "lan_ruleset.txt")
        local_dns = active_lines(ROOT / "dist" / "local_dns_ruleset.txt")
        self.assertEqual(len(lan_rules), 10)
        self.assertIn("DOMAIN,wpad.localdomain", lan_rules)
        self.assertIn("DOMAIN,wpad.localdomain", local_dns)
        self.assertNotIn(
            "DOMAIN,wpad.localdomain",
            active_lines(ROOT / "dist" / "force_direct_ruleset.txt"),
        )

    def test_china_enterprise_domains_and_asns_are_scoped(self):
        domains = active_lines(ROOT / "dist" / "china_enterprise_domainset.txt")
        self.assertEqual(
            set(domains),
            {
                ".1688.com", ".alibaba.com", ".alibabacloud.com", ".alicdn.com", ".alidns.com",
                ".aliexpress.com", ".alipay.com", ".alipayobjects.com", ".aliyun.com",
                ".aliyuncs.com", ".amap.com", ".autonavi.com", ".cainiao.com",
                ".dingtalk.com", ".taobao.com", ".tbcdn.cn", ".tmall.com",
                ".tmall.hk", ".ykimg.com", ".youku.com", ".alitrip.com",
                ".feizhu.com", ".fliggy.com", ".goofish.com", ".ele.me",
                ".elemecdn.com", ".freshhema.com", ".freshippo.com",
                ".pddpic.com", ".pinduoduo.com", ".yangkeduo.com",
                ".1mall.com", ".360buy.cn",
                ".360buy.com", ".360buy.com.cn", ".360buyimg.com", ".7fresh.com",
                ".baitiao.com", ".chinabank.com.cn", ".healthjd.com", ".jcloud.com",
                ".jcloudcs.com", ".jd.com", ".jd.hk", ".jdcloud.com", ".jclps.com",
                ".jdpay.com", ".jdwl.com", ".wangyin.com", ".yhd.com",
                ".yihaodian.com", ".yiyaojd.com", ".yunpei.com", ".yunxiu.com",
                ".dianping.com", ".meituan.com", ".neixin.cn", ".gaiaworkforce.com",
                ".flyertrip.com", ".flyert.com", ".flyert.com.cn", ".chinaebill.cn",
                ".95516.com", ".cup.com.cn", ".unionpay.com", ".zztfly.com", ".guanaitong.com",
                ".igeidao.com", ".ddxq.mobi", ".soboten.com", ".xinstall.top",
                ".starbucks.com.cn", ".cdn-go.cn", ".dnspod.cn", ".dnspod.com",
                ".caiyunapp.com", ".cityboxai.com", ".icitybox.cn",
                ".diditaxi.com.cn", ".udache.com", ".12306.cn", ".ceair.com",
                ".yaduo.com", ".icbc.com.cn", ".abchina.com",
                ".abchina.com.cn", ".boc.cn", ".ccb.cn", ".ccb.com", ".bankcomm.cn",
                ".bankcomm.com", ".cmbchina.com", ".95528.cn",
                ".spdb.com.cn", ".spdbccc.com.cn",
                ".gtimg.com", ".myqcloud.com", ".qcloud.com", ".qpic.cn", ".qq.com",
                ".qqmail.com", ".tencent-cloud.com", ".tencent.com",
                ".tencentcloud.com", ".tencentcloudapi.com", ".tenpay.com",
                ".trtcube-license.cn", ".wechat.com", ".wechatpay.com",
                ".weixinbridge.com", ".weiyun.com", ".189.cn",
                ".huazhu.com", ".umetrip.com", ".dcloud.net.cn", ".himalaya.com", ".qijizuopin.com", ".qingxuetang.com",
                ".xima.tv", ".ximalaya.com", ".ximalayaos.com", ".xiaoyastar.com",
                ".baidu.com", ".douyin.com", ".douyinpic.com", ".yangshipin.cn",
                ".wavpub.com", ".drbuho.com", ".geetest.com", ".tongdun.net",
                ".xiaoyuzhoufm.com", ".xyzcdn.net", ".openinstall.com", ".gcores.com",
                "cn-fp.apitd.net",
            },
        )
        self.assertEqual(
            [domain for domain in domains if not domain.startswith(".")],
            ["cn-fp.apitd.net"],
        )
        self.assertNotIn(".apitd.net", domains)
        self.assertEqual(
            active_lines(ROOT / "dist" / "china_enterprise_asn_ruleset.txt"),
            ["IP-ASN,24429", "IP-ASN,37963", "IP-ASN,45102", "IP-ASN,131486", "IP-ASN,137753", "IP-ASN,45090", "IP-ASN,132203", "IP-ASN,55967", "IP-ASN,55990", "IP-ASN,131516", "IP-ASN,17428"],
        )

    def test_china_carrier_asns_are_selected_operator_networks(self):
        self.assertEqual(
            active_lines(ROOT / "dist" / "china_carrier_asn_ruleset.txt"),
            ["IP-ASN,4134", "IP-ASN,4809", "IP-ASN,4812", "IP-ASN,4847", "IP-ASN,134238", "IP-ASN,4837", "IP-ASN,9929", "IP-ASN,17621", "IP-ASN,9808", "IP-ASN,24547", "IP-ASN,139887", "IP-ASN,134756", "IP-ASN,140717"],
        )


if __name__ == "__main__":
    unittest.main()
