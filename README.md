# Tailored-Rulesets

Surge rule data only. Credentials, subscription URLs, controller keys and browsing logs do not belong here.

## Profile order and purpose

1. `force_direct_domainset.txt` and `tailscale_control_domainset.txt`: explicit DIRECT exceptions.
2. External anti-ad subscription (kept outside this repository), then `reject_domainset.txt`: ordinary REJECT, without pre-matching.
3. `tailscale_private_ruleset.txt` and `tailscale_subnet_ruleset.txt`: dedicated Tailscale; REJECT until configured, never public fallback.
4. `proxy_path_override_domainset.txt` and `proxy_path_override_ruleset.txt`: explicit non-default proxy path (currently 12VPX Los Angeles).
5. `high_traffic_domainset.txt`: high-volume domains (initially googlevideo.com), currently 12VPX Los Angeles.
6. `media_domainset.txt`: combined Japan Smart.
7. `proxy_targets_domainset.txt`, `proxy_targets_ruleset.txt`, `microsoft_domainset.txt`, `ai_domainset.txt`, existing Google/Apple lists: Gate.
8. `china_domainset.txt`: lower-priority China DIRECT domains.
9. `lan_domainset.txt` and `lan_ip_ruleset.txt`: local DIRECT; remote Tailscale routes precede them.
10. `default_proxy_ruleset.txt`: Gate. The profile must still end with FINAL,Gate,dns-failed.

`local_dns_domainset.txt` assigns system DNS for local names; it is not an additional direct allowlist.
The profile reuses the routing files for Host DNS mappings: direct exceptions first, proxy exceptions next, China last.
IP rules cannot select a DNS resolver before resolution. Keep explicit no-resolve flags on IP rules.

## Formats

Every external data filename ends in `_domainset.txt` or `_ruleset.txt`, matching how the profile loads it.
DOMAIN-SET files contain hostnames only; a leading dot matches the name and its subdomains. Domain-only data uses this format.
RULE-SET files contain typed non-domain rules, without a policy field or FINAL. A mixed source is split into paired files, following the Apple domain/IP pattern.
Comment-only files intentionally have zero active entries. Microsoft and AI entries come from user-supplied lists; their completeness is not inferred from the service names.
Path overrides, default proxy targets, and LAN targets are split by data type. Their domain files contain names; corresponding ruleset files contain IP or process rules.
The former force_proxy/subscription_exit names are replaced by the two proxy_path_override files.
The former YouTube/heavy_load lists are consolidated into high_traffic_domainset.

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

