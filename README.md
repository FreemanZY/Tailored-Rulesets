# Tailored-Rulesets

Curated and generated rule data for Surge. This repository contains public rule files, reproducible generators, tests, and source snapshots. It does not contain complete Surge profiles, credentials, proxy subscriptions, controller keys, or traffic logs.

## Published data

All loadable files are published under `dist/` and declare their format in the filename:

- `*_domainset.txt` contains hostnames only. An entry with a leading dot matches both the named domain and its subdomains.
- `*_ruleset.txt` contains typed Surge rules such as `DOMAIN-WILDCARD`, `IP-CIDR`, `IP-CIDR6`, `IP-ASN`, or `PROCESS-NAME`.
- `*_generated_*` is produced from a documented upstream source or retained as a legacy generated snapshot.
- `*_manual_*` contains reviewed additions that are intentionally kept outside an automated source.

The main file families are:

| Family | Purpose |
| --- | --- |
| Apple, Google, and Microsoft | Generated service domains and network ranges, with separate manual domain additions |
| `ai_*` and `proxy_targets_*` | Curated service and target classifications |
| `high_traffic_*` | Domains and typed targets classified as bandwidth-intensive |
| `force_direct_*`, `reject_*`, `china_*`, and `lan_*` | Curated routing categories for a consuming profile to map to its own policies |
| `tailscale_*` | Optional control, node, and subnet targets for an overlay-network policy |
| `local_dns_*` | Names intended for resolver selection rather than route selection |

Policy names, policy-group topology, rule precedence, and fallback behavior belong in the consuming Surge profile. Published rule files do not embed those choices. Comment-only files are valid placeholders with no active entries.

`force_direct_ruleset.txt` currently contains a narrowly scoped `URL-REGEX` for plain HTTP WeChat MMTLS shortlinks sent directly to an IPv4 address. URL rules require Surge's HTTP engine; they do not inspect undecrypted HTTPS paths.

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

The initial entries in `apple_manual_domainset.txt` were migrated from the earlier generated snapshot when the official source did not preserve their previous matching scope. Their original provenance was not recorded, so they remain review candidates rather than official Apple declarations. The workflow never modifies the manual file.

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

`google_manual_domainset.txt` preserves 1,120 entries from the previous generated file. Their original provenance was not recorded, so they are retained as historical review candidates even when they overlap current official data. The workflow never modifies this manual file.

Run the offline consistency check with:

```shell
python scripts/update_google_rules.py --check
```

Generated outputs should not be edited manually. All three workflows update only their declared generated files after parsing and repository tests succeed.

## Manual data and DNS observations

Manual domains should be backed by an observed request hostname, TLS SNI, HTTP Host, or another reviewable source. A DNS-only CNAME target is not necessarily visible to Surge's domain rules and should not be copied automatically.

Resolver results, network ownership, or the location of an IP address are evidence for analysis rather than an automatic routing decision. Observations from different resolvers or egress paths should remain distinguishable when preparing candidates.

## Validation

Run all deterministic generator and published-file checks with:

```shell
python -m unittest discover -s tests -v
```

Before consuming a changed file, review the generated diff, verify its raw URL, and validate the final profile with the Surge version that will load it.
