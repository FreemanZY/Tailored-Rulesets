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
RULE-SET files contain typed non-domain rules, without a policy field or FINAL. A mixed source is split into paired files, following the Apple domain/IP pattern.
Comment-only files intentionally have zero active entries. Microsoft and AI seed entries came from user-supplied lists; their completeness is not inferred from the service names.
High-volume routing, default proxy targets, and LAN targets are split by data type. Their domain files contain names; corresponding ruleset files contain IP or process rules.
The former force_proxy/subscription_exit, proxy_path_override and YouTube/heavy_load lists are consolidated into the two high_traffic files.

Raw base URL:
https://raw.githubusercontent.com/FreemanZY/Tailored-Rulesets/refs/heads/main/dist/

The original Apple domain/IP and Google domain contents are preserved under generated filenames.
All policy choices belong in the consuming profile, not in these files.
An explicit direct entry overrides ads; a high-traffic entry overrides general service and China routing.
High traffic describes intended usage, not measured usage or an automatic bandwidth threshold.

## Generated and manual ownership

Each Apple, Google and Microsoft family has two generated outputs: `*_generated_domainset.txt` and `*_generated_ip_ruleset.txt`. These paths are reserved for a future GitHub Actions workflow and should not be edited manually after that workflow is enabled.

The repository does not yet contain a generator or workflow. Existing generated files are seed snapshots; Google and Microsoft generated IP files are empty placeholders. A filename alone does not mean scheduled updates are currently running.

`*_manual_domainset.txt` is maintained through reviewed observations for domains missing from the generated source, including CDN hosts. Add a CNAME target only when it is also observed as a request hostname, TLS SNI or HTTP Host; a DNS-only CNAME target is not necessarily visible to Surge domain rules.

## Maintenance

Until the GitHub Actions workflow is implemented, generated seed files are also maintained through reviewed commits.
New domains should be reviewed before committing. Future client observations and China/Bwgyus DNS probes produce candidates, not automatic direct rules.
Do not infer a permanent domain-to-IP mapping or grant direct access just because DNS returned a China IP.
Validate syntax and ordering, publish to main, verify raw URLs, then reload external resources on Surge.

