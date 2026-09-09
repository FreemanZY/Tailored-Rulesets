# Tailored-Rulesets

Surge rule data only. Credentials, subscription URLs, controller keys and browsing logs do not belong here.

## Profile order and purpose

1. `force_direct.txt` and `tailscale_control_ruleset.txt`: explicit DIRECT exceptions.
2. External anti-ad subscription (kept outside this repository), then `reject_ruleset.txt`: ordinary REJECT, without pre-matching.
3. `tailscale_private_ruleset.txt` and `tailscale_subnet_ruleset.txt`: dedicated Tailscale; REJECT until configured, never public fallback.
4. `proxy_path_override_ruleset.txt`: explicit non-default proxy path (currently 12VPX Los Angeles).
5. `high_traffic_domainset.txt`: high-volume domains (initially googlevideo.com), currently 12VPX Los Angeles.
6. `media_ruleset.txt`: combined Japan Smart.
7. `proxy_targets_ruleset.txt`, `microsoft_service.txt`, `ai_service.txt`, existing Google/Apple lists: Gate.
8. `china_domainset.txt`: lower-priority China DIRECT domains.
9. `lan_ip_ruleset.txt`: local DIRECT; remote Tailscale routes precede it.
10. `default_proxy_ruleset.txt`: Gate. The profile must still end with FINAL,Gate,dns-failed.

`local_dns_ruleset.txt` assigns system DNS for local names; it is not an additional direct allowlist.
The profile reuses the routing files for Host DNS mappings: direct exceptions first, proxy exceptions next, China last.
IP rules cannot select a DNS resolver before resolution. Keep explicit no-resolve flags on IP rules.

## Formats

Files named domainset contain hostnames only; a leading dot matches the name and its subdomains.
Other files contain Surge RULE-SET entries, without a policy field or FINAL.
Comment-only files intentionally have zero active entries. Missing original Microsoft/AI contents have not been invented.
The former force_proxy/subscription_exit names are replaced by proxy_path_override_ruleset.
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
