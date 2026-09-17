# Classification Policy

## Output Categories

### Core DOMAIN-SET

Use `dist/china_enterprise_domainset.txt` when current high-confidence evidence supports a stable enterprise or public-service root and suffix-wide matching is appropriate.

Strong evidence includes:

- an official endpoint, firewall, allowlist, or security-scope document that publishes the wildcard or root;
- an official corporate, product, privacy, or legal page that consistently operates on the root, when the root is dedicated to that enterprise service and is not a shared customer namespace;
- multiple official properties that establish both ownership and the intended suffix scope.

A leading dot matches the root and every subdomain. Do not add it merely because one observed host belongs to the brand.

### Manual RULE-SET

Use `dist/china_enterprise_manual_ruleset.txt` when direct routing is justified but the supported scope is narrower:

- an observed exact functional endpoint associated with a verified China enterprise;
- a CNAME or CDN delivery hostname whose use is verified but whose parent is shared;
- an older official endpoint source that no longer establishes a current core suffix;
- an official exact hostname without evidence that sibling subdomains share the same purpose.

Prefer `DOMAIN,<exact-host>`. Use `DOMAIN-SUFFIX` only when the source itself establishes wildcard or suffix behavior.

### Keep FINAL or No Addition

Keep the target on FINAL, or decline to add it, when ownership remains uncertain, the service is not a China enterprise service, routing need is unproven, or only weak third-party evidence exists.

## Evidence Levels

| Level | Evidence | Usual result |
| --- | --- | --- |
| A | Current official endpoint list, firewall list, wildcard, security scope, or service documentation | Core suffix when scope is explicit |
| B | Current official company, product, privacy, or legal pages establish a dedicated service root | Core suffix if shared-hosting risk is low |
| C | Official exact endpoint, observed traffic plus official brand linkage, or historical official list | Exact manual rule |
| D | Passive DNS, certificate data, WHOIS, third-party domain databases, ASN, or IP geolocation only | Supporting evidence only; normally keep FINAL |

Third-party evidence may locate better primary sources but cannot by itself promote a domain to the core set.

## China-Enterprise Test

Confirm the operator, not merely the audience or server location. A `.cn` suffix, Chinese IP, Chinese CDN node, ICP record, or Chinese-language page is not sufficient alone. Distinguish:

- a mainland China operating entity and service;
- a foreign service using a China CDN;
- an overseas branch of a China group;
- a shared platform serving unrelated tenants.

When the enterprise is Chinese but the hostname is a shared CDN or cloud hostname, keep the rule exact unless the provider publishes a dedicated suffix for that service.

## Scope and Conflict Rules

- Domain evidence outranks IP and ASN evidence for service identity.
- A CNAME identifies a delivery path, not necessarily ownership of the requested service.
- Do not add an ASN rule as part of this workflow.
- Preserve higher-priority explicit proxy or reject decisions. Report conflicts rather than silently moving them.
- If a core suffix is approved, remove exact manual entries covered by it in the same change.
- If an automated official source already covers the target with equivalent scope, remove the redundant manual entry instead of adding another rule.
- Do not broaden from `host.example.com` to `.example.com` when the parent contains unrelated products, customer-controlled tenants, international services, or unknown subdomains.

## Required Proposal Fields

For each input domain include:

1. current rule coverage;
2. operator and service;
3. primary evidence URLs;
4. ownership and scope confidence;
5. recommended category and exact rule text;
6. overmatching and shared-infrastructure risk;
7. redundant entries or documentation changes caused by acceptance.
