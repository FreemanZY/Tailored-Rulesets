# Tailored-Rulesets

Surge rule data only. Credentials, subscription URLs, controller keys and browsing logs do not belong here.

## Profile order and purpose

1. `force_direct_domainset.txt` and `tailscale_control_domainset.txt`: explicit DIRECT exceptions.
2. External anti-ad subscription (kept outside this repository), then `reject_domainset.txt`: ordinary REJECT, without pre-matching.
3. `tailscale_private_ruleset.txt` and `tailscale_subnet_ruleset.txt`: dedicated Tailscale; REJECT until configured, never public fallback.
4. `high_traffic_domainset.txt` and `high_traffic_ruleset.txt`: high-volume traffic through 12VPX Los Angeles.
5. `proxy_targets_domainset.txt`, `proxy_targets_ruleset.txt`, `ai_domainset.txt`, and the generated/manual Apple, Google and Microsoft lists: Gate.
6. `china_domainset.txt`: lower-priority China DIRECT domains.
7. `lan_domainset.txt` and `lan_ip_ruleset.txt`: local DIRECT; remote Tailscale routes precede them.

The profile ends with `FINAL,Gate,dns-failed`; no separate default-proxy file is needed.

`local_dns_domainset.txt` assigns system DNS for local names; it is not an additional direct allowlist.
The profile reuses the routing files for Host DNS mappings: direct exceptions first, proxy exceptions next, China last.
IP rules cannot select a DNS resolver before resolution. Keep explicit no-resolve flags on IP rules.

## Formats

Every external data filename ends in `_domainset.txt` or `_ruleset.txt`, matching how the profile loads it.
DOMAIN-SET files contain hostnames only; a leading dot matches the name and its subdomains. Domain-only data uses this format.
RULE-SET files contain typed rules, without a policy field or FINAL. Mixed sources use RULE-SET for IP data and domain patterns that DOMAIN-SET cannot express precisely.
Comment-only files intentionally have zero active entries. AI seed entries came from a user-supplied list; its completeness is not inferred from the service name.
High-volume routing, default proxy targets, and LAN targets are split by data type. Their domain files contain names; corresponding ruleset files contain IP or process rules.
The former force_proxy/subscription_exit, proxy_path_override and YouTube/heavy_load lists are consolidated into the two high_traffic files.

Raw base URL:
https://raw.githubusercontent.com/FreemanZY/Tailored-Rulesets/refs/heads/main/dist/

The original Apple domain/IP and Google domain contents are preserved under generated filenames.
All policy choices belong in the consuming profile, not in these files.
An explicit direct entry overrides ads; a high-traffic entry overrides general service and China routing.
High traffic describes intended usage, not measured usage or an automatic bandwidth threshold.

## Generated and manual ownership

Apple and Google retain paired `*_generated_domainset.txt` and `*_generated_ip_ruleset.txt` outputs. Microsoft uses `microsoft_generated_domainset.txt` plus the mixed `microsoft_generated_ruleset.txt`, because its official source includes partial-label and middle-label wildcards that require `DOMAIN-WILDCARD` alongside IP rules.

Microsoft generated files are owned by `scripts/update_microsoft_rules.py` and `.github/workflows/update-microsoft-rules.yml`; do not edit them manually. The workflow checks the official version daily and fetches all four endpoint instances only when a version changes. Google generated IP remains an empty placeholder until its own authoritative source and workflow are implemented.

The Microsoft source is the official Microsoft 365 endpoint web service. The generated union includes Worldwide, China (21Vianet), USGovDoD and USGovGCCHigh; all service areas, categories, required/optional records, IPv4 and IPv6 are retained. `sources/microsoft_endpoints.json` preserves version, region, ports, category, requirement, ExpressRoute and notes for audit. Routing policy and port restrictions are intentionally not encoded in generated data.

For Microsoft URL conversion, exact source names stay exact and a source `*.example.com` becomes `.example.com` by project convention. Partial-label or middle-label wildcards remain `DOMAIN-WILDCARD` rules, so they are not broadened into unrelated suffixes. Run `python scripts/update_microsoft_rules.py --check` for an offline consistency check.

`*_manual_domainset.txt` is maintained through reviewed observations for domains missing from the generated source, including CDN hosts. Add a CNAME target only when it is also observed as a request hostname, TLS SNI or HTTP Host; a DNS-only CNAME target is not necessarily visible to Surge domain rules.

## Maintenance

New manual domains should be reviewed before committing. Future client observations and China/Bwgyus DNS probes produce candidates, not automatic direct rules.
Do not infer a permanent domain-to-IP mapping or grant direct access just because DNS returned a China IP.
Validate syntax and ordering, publish to main, verify raw URLs, then reload external resources on Surge.

