# Tailored-Rulesets

Curated and generated rule data for Surge. This repository contains public rule files, reproducible generators, tests, and source snapshots. It does not contain complete Surge profiles, credentials, proxy subscriptions, controller keys, or traffic logs.

## Published data

All loadable files are published under `dist/` and declare their format in the filename:

- `*_domainset.txt` contains hostnames only. An entry with a leading dot matches both the named domain and its subdomains.
- `*_ruleset.txt` contains typed Surge rules such as `DOMAIN-WILDCARD`, `IP-CIDR`, `IP-CIDR6`, `IP-ASN`, or `PROCESS-NAME`.
- `*_generated_*` is produced from a documented upstream source or retained as a legacy generated snapshot.
- `*_manual_ruleset.txt` contains reviewed additions kept outside automated sources. A manual category uses one typed RULE-SET so domains, IP ranges, and narrow regular expressions can be maintained together.

The main file families are:

| Family | Purpose |
| --- | --- |
| Apple, Google, and Microsoft | Official generated service data plus one manual RULE-SET per vendor |
| `ai_manual_ruleset.txt` and `proxy_targets_ruleset.txt` | Manually maintained service and target classifications |
| `high_traffic_ruleset.txt` | Domains and typed targets classified as bandwidth-intensive |
| `force_direct_ruleset.txt`, `reject_ruleset.txt`, `china_manual_ruleset.txt`, and `lan_ruleset.txt` | Manually maintained routing categories for a consuming profile |
| `tailscale_*` | Optional control, node, and subnet targets for an overlay-network policy |
| `local_dns_*` | Names intended for resolver selection rather than route selection |

Policy names, policy-group topology, rule precedence, and fallback behavior belong in the consuming Surge profile. Published rule files do not embed those choices. Comment-only files are valid placeholders with no active entries.

`china_enterprise_domainset.txt` contains a reviewed core set of major China enterprise and public-service domains. Alibaba coverage includes the current official roots for Taobao, Tmall and Tmall Global, Fliggy, Idle Fish, and Taobao Instant Commerce. JD coverage includes the current official China service roots and JD Cloud Distribution; the overseas JOYBUY, Russia, Thailand, and Indonesia roots are intentionally omitted from this China-direct set. Meituan and Dianping use their officially identified `meituan.com` and `dianping.com` roots, while observed `meituan.net` CDN hosts remain exact rules in the manual set. Didi coverage is limited to the China mobility roots supported by its official service and privacy pages; observed `didi.cn`, `didistatic.com`, and `xiaojukeji.com` hosts remain exact manual rules. China Railway 12306, China Eastern Airlines, and Atour use their officially identified `12306.cn`, `ceair.com`, and `yaduo.com` roots. The Huazhu entry uses the official `*.huazhu.com` scope to cover both the root and its subdomains. Umetrip uses its official `umetrip.com` root for services operated by Travelsky Mobile Technology. Seven Ximalaya suffixes are based on the domains reconfirmed by the 2023 XMSRC scope. `china_enterprise_asn_ruleset.txt` adds network-owner matches for Alibaba AS24429/AS37963/AS45102, JD AS131486/AS137753, Tencent AS45090/AS132203, Baidu AS55967, Huawei Cloud China AS55990, Jinhua Weian InfoTech AS131516, and 21Vianet AS17428. The domain set is the primary classifier; ASN rules are a broader fallback because cloud and CDN networks can also host third-party traffic. Consumers should place ASN matches after explicit domain policies and must not treat network ownership as proof that a request belongs to the corresponding brand.

`china_enterprise_manual_ruleset.txt` keeps manually observed China enterprise endpoints that are not covered by the reviewed core suffixes. Its comments separate Alibaba, WeChat/Weixin, Meituan/Dianping, Xiaomi/Mijia, Didi, Ximalaya, CITIC, Tencent/QQ Music, Luckin, Caiyun, Baidu, Volcengine, NetEase Yunxin, CMB Wing Lung Bank, and China Unicom observations. Four legacy Taobao suffixes remain here because their public evidence is an older official developer allowlist. The Ximalaya group also retains `xmcdn.com` and `zhishidashi.com` from the official XMSRC v2.1 scope because they were not repeated in the narrower 2023 event list. Exact business hosts remain `DOMAIN` rules when they are delivered through a shared cloud or CDN ASN, avoiding an ASN-wide classification of unrelated tenants. `force_direct_ruleset.txt` retains operational exceptions and entries whose ownership or purpose still needs review; `reject_ruleset.txt` contains reviewed rejection observations. Exact hosts remain `DOMAIN` rules unless the source explicitly used suffix semantics; generated actions never modify manual rulesets.

The legacy import deliberately excludes private infrastructure names, conflicting direct copies of telemetry endpoints, broad duplicate MMTLS regular expressions, and four historical CDN `/32` observations whose present ownership and exclusivity were not established. `china_enterprise_manual_ruleset.txt` retains the narrower validated MMTLS URL rule.

`china_carrier_asn_ruleset.txt` separately lists selected mainland backbone, provincial, inter-exchange, and IDC networks of China Telecom, China Unicom, and China Mobile. International networks such as CTGNet AS23764, China Unicom Global AS10099, and China Mobile International AS58453 are intentionally excluded. Carrier ASN matching is extremely broad and can include residential users, enterprise access, hosting, and unrelated content; profiles should place it after all explicit domain policies and keep it independently removable.

Reference sources for this curated data include [Alibaba Group businesses](https://www.alibabagroup.com/en-US/about-alibaba-businesses-1489022236378529792), [Alibaba Cloud firewall/proxy domains](https://help.aliyun.com/zh/management-console/configure-a-local-firewall-or-proxy-to-access-alibaba-cloud-services), [JD's official JSRC V9.1 scope](https://security-jsrc.s3.cn-north-1.jdcloud-oss.com/JSRC-V9.1.pdf), [Meituan's platform definition](https://rules-center.meituan.com/m/detail/guize/1408?activeRule=1), [Dianping's privacy policy](https://rules-center.meituan.com/m/detail/guize/605?activeRule=1), [Didi's official website privacy notice](https://www.didiglobal.com/infocompliance), [Didi's China driver-service website](https://www.udache.com/), [China Railway's official-channel notice](https://www.12306.cn/mormhweb/zxdt/202412/t20241211_43192.html), [China Eastern Airlines' MUSRC scope](https://src.ceair.com/announcement/detail?id=1), [Atour's corporate website](https://www.yaduo.com/), [Atour's privacy policy](https://wechat.yaduo.com/atour/static/privacy), [Tencent products](https://www.tencent.com/who-we-are/), [Tencent Cloud endpoints](https://intl.cloud.tencent.com/document/product/494/7246), [Huazhu's official security scope](https://sec.huazhu.com/index.php?a=view&c=page&id=14&m=), [Huazhu business API endpoints](https://docs.huazhu.com/b2b/api/api/environment/), [Umetrip's privacy statement](https://www.umetrip.com/PrivacyOptimization/privacy.html), [Travelsky Mobile Technology's company profile](https://www.umetrip.com.cn/company), [Ximalaya's 2023 XMSRC scope](https://security.ximalaya.com/announcement/msg/127), [Ximalaya's XMSRC v2.1 scope](https://security.ximalaya.com/announcement/msg/54), [Huawei Cloud China peering data](https://www.peeringdb.com/asn/55990), [China Telecom Global Internet](https://www.chinatelecom-ctap.com/solutions/internet/), [China Unicom DIA](https://kr.chinaunicomglobal.com/products-dia.php), [Alibaba peering](https://peering.aliyun.com/), [Tencent peering](https://peering.tencent.com/), PeeringDB, and the relevant APNIC registration records. These files are curated snapshots and are not automatically synchronized with vendor changes.

`china_enterprise_manual_ruleset.txt` contains a narrowly scoped `URL-REGEX` for plain HTTP WeChat MMTLS shortlinks sent directly to an IPv4 address. URL rules require Surge's HTTP engine; they do not inspect undecrypted HTTPS paths.

Raw base URL:

```text
https://raw.githubusercontent.com/FreemanZY/Tailored-Rulesets/refs/heads/main/dist/
```

A consuming profile can append a filename to that base URL and select its own policy, for example:

```ini
DOMAIN-SET,<raw-domainset-url>,<policy>
RULE-SET,<raw-ruleset-url>,<policy>,no-resolve
```

The core domain set includes official website roots for ICBC, ABC, BOC, CCB, Bank of Communications, CMB, and SPDB. It retains ABC's still-accessible `abchina.com`, includes CCB's current `ccb.cn`, and covers SPDB's alternate `95528.cn` and credit-card `spdbccc.com.cn`. ABC's older corporate-banking `95599.cn` and BOC's global `bankofchina.com` are omitted pending an explicit routing need. Overseas branch hosts also exist under `ccb.com`, `bankcomm.com`, and `cmbchina.com`; place specific host overrides before a China-direct policy for those branches. QQ Music is covered by Tencent's `qq.com`; observed shared-CDN delivery hosts remain exact entries in the manual set.

Bank sources: [ICBC domain guidance](https://www.icbc.com.cn/icbc/announceme/363.htm), [ABC domain migration](https://www.abchina.com/cn/PersonalServices/SvcBulletin/202207/t20220721_2168645.htm), [BOC site](https://www.boc.cn/), [CCB site](https://www.ccb.cn/chn/home/index.shtml), [Bank of Communications](https://www.bankcomm.com/BankCommSite/default.shtml), [CMB site](https://www.cmbchina.com/), [SPDB alternate address notice](https://www.spdb.com.cn/home/sygg/202607/t20260713_18247188.shtml), and [SPDB credit cards](https://www.spdbccc.com.cn/).

Pinduoduo's platform and open portal use `pinduoduo.com` and `yangkeduo.com`; its own published documents and media use `pddpic.com`. The latter also contains international-platform promotion documents, so an overseas host may need a higher-priority routing override. Freshippo's current `freshippo.com` is reached both directly and from the Alibaba Group-linked `freshhema.com`; `1688.com` was already in the core set. No comprehensive vendor endpoint inventory was found, and unrelated CDN or unverified brand-like suffixes are not added. Sources: [Pinduoduo platform agreement](https://pfile.pddpic.com/galerie-go/open_sdk/9372cfe1-780a-4b8b-95e1-4405de1cf43c.pdf), [Pinduoduo open platform](https://open.yangkeduo.com/), [Pinduoduo published privacy notice](https://pfile.pddpic.com/galerie-go/mms_file/3a0bdcc8-0b73-4cb4-ae9c-ff34facaed2c.pdf), [Alibaba Group business links](https://www.alibabagroup.com/en-US/about-alibaba-businesses-1747800973536919552), [Freshippo app](https://www.freshippo.com/down/app.html), and [1688 overview](https://www.alibabagroup.com/en-US/about-alibaba-businesses-1941299332078632960).

## Automated sources

### Apple

`scripts/update_apple_rules.py` reads Apple's official [enterprise network article](https://support.apple.com/en-us/101555). The daily workflow parses every endpoint table, the firewall hostname pattern, and the published IPv4 and IPv6 ranges.

Links used by the automation and its consumers:

- Official source: <https://support.apple.com/en-us/101555>
- GitHub Actions workflow: <https://github.com/FreemanZY/Tailored-Rulesets/actions/workflows/update-apple-rules.yml>
- Structured source snapshot: <https://github.com/FreemanZY/Tailored-Rulesets/blob/main/sources/apple_enterprise_networks.json>
- DOMAIN-SET raw file: <https://raw.githubusercontent.com/FreemanZY/Tailored-Rulesets/refs/heads/main/dist/apple_generated_domainset.txt>
- IP RULE-SET raw file: <https://raw.githubusercontent.com/FreemanZY/Tailored-Rulesets/refs/heads/main/dist/apple_generated_ip_ruleset.txt>

The structured snapshot in `sources/apple_enterprise_networks.json` retains each source row with its section, ports, protocols, operating systems, description, proxy-support field, links, publication date, and recent-change notes. A semantic hash prevents presentation-only HTML changes from rewriting the generated files.

Exact source hostnames remain exact. A standard source wildcard such as `*.example.com` becomes `.example.com`; wildcard forms that cannot be represented precisely by DOMAIN-SET cause the update to fail for review. The Apple workflow owns:

- `dist/apple_generated_domainset.txt`
- `dist/apple_generated_ip_ruleset.txt`
- `sources/apple_enterprise_networks.json`

The initial entries in `apple_manual_ruleset.txt` were migrated from the earlier generated snapshot when the official source did not preserve their previous matching scope. Their original provenance was not recorded, so they remain review candidates rather than official Apple declarations. The workflow never modifies the manual file.

Run the offline consistency check with:

```shell
python scripts/update_apple_rules.py --check
```

### Microsoft 365 and Power Apps

`scripts/update_microsoft_rules.py` combines the official Microsoft 365 endpoint web service with the required-services table from the official Power Apps limits and configuration page. Microsoft 365 covers Worldwide, China (21Vianet), USGovDoD, and USGovGCCHigh; all service areas, categories, required and optional records, IPv4, and IPv6 are retained. Power Apps is parsed from the Microsoft-maintained Markdown backing the Learn page on every run.

Links used by the automation and its consumers:

- Official web service documentation: <https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service?view=o365-worldwide>
- API base: <https://endpoints.office.com>
- Official Power Apps endpoint table: <https://learn.microsoft.com/en-us/power-apps/limits-and-config>
- Microsoft-maintained Power Apps Markdown: <https://raw.githubusercontent.com/MicrosoftDocs/powerapps-docs/main/powerapps-docs/limits-and-config.md>
- GitHub Actions workflow: <https://github.com/FreemanZY/Tailored-Rulesets/actions/workflows/update-microsoft-rules.yml>
- Structured source snapshot: <https://github.com/FreemanZY/Tailored-Rulesets/blob/main/sources/microsoft_endpoints.json>
- DOMAIN-SET raw file: <https://raw.githubusercontent.com/FreemanZY/Tailored-Rulesets/refs/heads/main/dist/microsoft_generated_domainset.txt>
- Mixed RULE-SET raw file: <https://raw.githubusercontent.com/FreemanZY/Tailored-Rulesets/refs/heads/main/dist/microsoft_generated_ruleset.txt>

`sources/microsoft_endpoints.json` preserves the Microsoft 365 source versions, instances, ports, categories, requirement flags, ExpressRoute flags, and notes. It also preserves each Power Apps table row, protocol, usage description, document date, exclusions, and a semantic hash. Standard `*.` patterns become DOMAIN-SET suffixes. Partial-label and middle-label wildcards remain `DOMAIN-WILDCARD` entries in the mixed ruleset. The documented Dynamics CRM region template is expanded into its published numbered forms; local-only `localhost` and `127.0.0.1` entries remain source metadata and are not emitted as routing rules.

`dist/microsoft_manual_ruleset.txt` separately keeps reviewed Microsoft endpoints that are not covered by either official automated source. The workflow never modifies this manual file.

The Microsoft workflow owns:

- `dist/microsoft_generated_domainset.txt`
- `dist/microsoft_generated_ruleset.txt`
- `sources/microsoft_endpoints.json`

Run the offline consistency check with:

```shell
python scripts/update_microsoft_rules.py --check
```

### Google

`scripts/update_google_rules.py` reads six fixed Google documentation pages and two official IP-range feeds. It does not recursively crawl documentation links.

HTML sources:

- [Google Workspace host allowlist](https://knowledge.workspace.google.com/admin/getting-started/set-up-a-google-workspace-host-name-allowlist)
- [Firewall and proxy settings](https://knowledge.workspace.google.com/admin/security/firewall-and-proxy-settings)
- [Obtain Google IP address ranges](https://knowledge.workspace.google.com/admin/security/obtain-google-ip-address-ranges)
- [ChromeOS hostname allowlist](https://support.google.com/chrome/a/answer/6334001)
- [Meet network requirements](https://knowledge.workspace.google.com/admin/meet/prepare-your-network-for-meet-meetings-and-live-streams)
- [Drive and Sites firewall settings](https://knowledge.workspace.google.com/admin/drive/drive-and-sites-firewall-and-proxy-settings)

IP sources:

- [Google service prefixes (`goog.json`)](https://www.gstatic.com/ipranges/goog.json)
- [Customer Google Cloud prefixes (`cloud.json`)](https://www.gstatic.com/ipranges/cloud.json)

The generator computes the CIDR difference `goog.json - cloud.json` with Python's IP network operations. This prevents customer Google Cloud prefixes from being classified wholesale as Google service traffic. Meet media ranges retain their separate source relationship in the snapshot.

Exact hostnames remain exact, standard `*.` patterns become DOMAIN-SET suffix entries, and partial-label patterns remain `DOMAIN-WILDCARD` rules. Numeric `[0-9]` templates are expanded. Country placeholders for Google Account hosts use the documented compatibility expansion `DOMAIN-WILDCARD,accounts.google.*`; this broader interpretation is marked in the output and source snapshot.

Links used by the automation and its consumers:

- GitHub Actions workflow: <https://github.com/FreemanZY/Tailored-Rulesets/actions/workflows/update-google-rules.yml>
- Structured source snapshot: <https://github.com/FreemanZY/Tailored-Rulesets/blob/main/sources/google_endpoints.json>
- DOMAIN-SET raw file: <https://raw.githubusercontent.com/FreemanZY/Tailored-Rulesets/refs/heads/main/dist/google_generated_domainset.txt>
- Mixed RULE-SET raw file: <https://raw.githubusercontent.com/FreemanZY/Tailored-Rulesets/refs/heads/main/dist/google_generated_ruleset.txt>

The Google workflow owns:

- `dist/google_generated_domainset.txt`
- `dist/google_generated_ruleset.txt`
- `sources/google_endpoints.json`

`google_manual_ruleset.txt` preserves 1,120 entries from the previous generated file. Their original provenance was not recorded, so they are retained as historical review candidates even when they overlap current official data. The workflow never modifies this manual file.

Run the offline consistency check with:

```shell
python scripts/update_google_rules.py --check
```

Generated outputs should not be edited manually. All three workflows update only their declared generated files after parsing and repository tests succeed.

## Manual data and DNS observations

Manual domains should be backed by an observed request hostname, TLS SNI, HTTP Host, or another reviewable source. A DNS-only CNAME target is not necessarily visible to Surge's domain rules and should not be copied automatically.

Each manually maintained category uses one `*_ruleset.txt` file. Use `DOMAIN` for an exact hostname, `DOMAIN-SUFFIX` only when suffix scope is intentional, and typed IP or URL rules when needed. Group related entries with comments inside the file. DOMAIN-SET files are reserved for generated output or reviewed data derived from official sources.

Resolver results, network ownership, or the location of an IP address are evidence for analysis rather than an automatic routing decision. Observations from different resolvers or egress paths should remain distinguishable when preparing candidates.

## Validation

Run all deterministic generator and published-file checks with:

```shell
python -m unittest discover -s tests -v
```

Before consuming a changed file, review the generated diff, verify its raw URL, and validate the final profile with the Surge version that will load it.
