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

`china_enterprise_domainset.txt` contains a reviewed core set of Alibaba, JD, and Tencent service domains. `china_enterprise_asn_ruleset.txt` adds network-owner matches for Alibaba AS24429/AS37963/AS45102, JD AS131486/AS137753, and Tencent AS45090/AS132203. The domain set is the primary classifier; ASN rules are a broader fallback because cloud and CDN networks can also host third-party traffic. Consumers should place ASN matches after explicit domain policies and must not treat network ownership as proof that a request belongs to the corresponding brand.

`china_enterprise_manual_ruleset.txt` keeps manually observed China enterprise endpoints that are not covered by the reviewed core suffixes. Its comments separate Alibaba, WeChat/Weixin, Meituan/Dianping, Xiaomi/Mijia, Didi, Huazhu, Luckin, Caiyun, China Railway, Baidu, Volcengine, NetEase Yunxin, CMB Wing Lung Bank, and China Unicom observations. `force_direct_ruleset.txt` retains operational exceptions and entries whose ownership or purpose still needs review; `reject_ruleset.txt` contains reviewed rejection observations. Exact hosts remain `DOMAIN` rules unless the source explicitly used suffix semantics; generated actions never modify manual rulesets.

The legacy import deliberately excludes private infrastructure names, conflicting direct copies of telemetry endpoints, broad duplicate MMTLS regular expressions, and four historical CDN `/32` observations whose present ownership and exclusivity were not established. `china_enterprise_manual_ruleset.txt` retains the narrower validated MMTLS URL rule.

`china_carrier_asn_ruleset.txt` separately lists the mainland backbones of China Telecom (AS4134/AS4809), China Unicom (AS4837/AS9929), and China Mobile (AS9808). International networks such as CTGNet AS23764, China Unicom Global AS10099, and China Mobile International AS58453 are intentionally excluded. Carrier ASN matching is extremely broad and can include residential users, enterprise access, hosting, and unrelated content; profiles should place it after all explicit domain policies and keep it independently removable.

Reference sources for this curated data include [Alibaba Group businesses](https://www.alibabagroup.com/en-US/about-alibaba-businesses-1489022236378529792), [Alibaba Cloud firewall/proxy domains](https://help.aliyun.com/zh/management-console/configure-a-local-firewall-or-proxy-to-access-alibaba-cloud-services), [JD's official security scope](https://security.jd.com/static/JSRC-V7.0.pdf), [Tencent products](https://www.tencent.com/who-we-are/), [Tencent Cloud endpoints](https://intl.cloud.tencent.com/document/product/494/7246), [China Telecom Global Internet](https://www.chinatelecom-ctap.com/solutions/internet/), [China Unicom DIA](https://kr.chinaunicomglobal.com/products-dia.php), [Alibaba peering](https://peering.aliyun.com/), [Tencent peering](https://peering.tencent.com/), PeeringDB, and the relevant APNIC registration records. These files are curated snapshots and are not automatically synchronized with vendor changes.

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

### Microsoft 365

`scripts/update_microsoft_rules.py` uses the official Microsoft 365 endpoint web service and combines Worldwide, China (21Vianet), USGovDoD, and USGovGCCHigh. All service areas, categories, required and optional records, IPv4, and IPv6 are retained.

Links used by the automation and its consumers:

- Official web service documentation: <https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service?view=o365-worldwide>
- API base: <https://endpoints.office.com>
- GitHub Actions workflow: <https://github.com/FreemanZY/Tailored-Rulesets/actions/workflows/update-microsoft-rules.yml>
- Structured source snapshot: <https://github.com/FreemanZY/Tailored-Rulesets/blob/main/sources/microsoft_endpoints.json>
- DOMAIN-SET raw file: <https://raw.githubusercontent.com/FreemanZY/Tailored-Rulesets/refs/heads/main/dist/microsoft_generated_domainset.txt>
- Mixed RULE-SET raw file: <https://raw.githubusercontent.com/FreemanZY/Tailored-Rulesets/refs/heads/main/dist/microsoft_generated_ruleset.txt>

`sources/microsoft_endpoints.json` preserves the source versions, instances, ports, categories, requirement flags, ExpressRoute flags, and notes. Standard `*.` patterns become DOMAIN-SET suffixes. Partial-label and middle-label wildcards remain `DOMAIN-WILDCARD` entries in the mixed ruleset.

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
