# Tailored-Rulesets

Surge rule data only. Credentials, subscription URLs, controller keys and browsing logs do not belong here.

## Profile order and purpose

1. `force_direct_domainset.txt` and `tailscale_control_domainset.txt`: explicit DIRECT exceptions.
2. External anti-ad subscription (kept outside this repository), then `reject_domainset.txt`: ordinary REJECT, without pre-matching.
3. `tailscale_private_ruleset.txt` and `tailscale_subnet_ruleset.txt`: dedicated Tailscale; REJECT until configured, never public fallback.
4. `high_traffic_domainset.txt` and `high_traffic_ruleset.txt`: high-volume traffic through 12VPX Los Angeles.
5. `proxy_targets_domainset.txt`, `proxy_targets_ruleset.txt`, `microsoft_domainset.txt`, `ai_domainset.txt`, existing Google/Apple lists: Gate.
6. `china_domainset.txt`: lower-priority China DIRECT domains.
7. `lan_domainset.txt` and `lan_ip_ruleset.txt`: local DIRECT; remote Tailscale routes precede them.
8. `default_proxy_ruleset.txt`: Gate. The profile must still end with FINAL,Gate,dns-failed.

`local_dns_domainset.txt` assigns system DNS for local names; it is not an additional direct allowlist.
The profile reuses the routing files for Host DNS mappings: direct exceptions first, proxy exceptions next, China last.
IP rules cannot select a DNS resolver before resolution. Keep explicit no-resolve flags on IP rules.

## Formats

Every external data filename ends in `_domainset.txt` or `_ruleset.txt`, matching how the profile loads it.
DOMAIN-SET files contain hostnames only; a leading dot matches the name and its subdomains. Domain-only data uses this format.
RULE-SET files contain typed non-domain rules, without a policy field or FINAL. A mixed source is split into paired files, following the Apple domain/IP pattern.
Comment-only files intentionally have zero active entries. Microsoft and AI entries come from user-supplied lists; their completeness is not inferred from the service names.
High-volume routing, default proxy targets, and LAN targets are split by data type. Their domain files contain names; corresponding ruleset files contain IP or process rules.
The former force_proxy/subscription_exit, proxy_path_override and YouTube/heavy_load lists are consolidated into the two high_traffic files.

Raw base URL:
https://raw.githubusercontent.com/FreemanZY/Tailored-Rulesets/refs/heads/main/dist/

Existing apple_domainset.txt, apple_ip_ruleset.txt and google_domainset.txt are preserved.
All policy choices belong in the consuming profile, not in these files.
An explicit direct entry overrides ads; an explicit proxy-path entry overrides high-traffic and China routing.
High traffic describes intended usage, not measured usage or an automatic bandwidth threshold.

## Maintenance

This repository currently has no rule generator or scheduled updater; dist files are maintained directly.
New domains should be reviewed before committing. Future client observations and China/Bwgyus DNS probes produce candidates, not automatic direct rules.
Do not infer a permanent domain-to-IP mapping or grant direct access just because DNS returned a China IP.
Validate syntax and ordering, publish to main, verify raw URLs, then reload external resources on Surge.

