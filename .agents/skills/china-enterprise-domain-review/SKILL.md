---
name: china-enterprise-domain-review
description: Research one or more observed domains, determine whether they belong to a mainland China enterprise or public-service operator, and propose exact manual rules or high-confidence core DOMAIN-SET suffixes for Tailored-Rulesets. Use for evidence-based classification into china_enterprise_manual_ruleset.txt or china_enterprise_domainset.txt; do not use for generic Surge configuration, non-China service routing, or generated vendor feeds.
---

# China Enterprise Domain Review

Use this workflow to turn observed domains into a reviewable classification proposal. The user's instructions take precedence over this skill.

## Inspect Before Research

Normalize and inspect every supplied domain with:

```powershell
python .agents/skills/china-enterprise-domain-review/scripts/inspect_rule_coverage.py --pretty <domain> [<domain> ...]
```

Run it from the `Tailored-Rulesets` repository. Treat its output as current-rule evidence only; it does not establish ownership.

Read [references/classification-policy.md](references/classification-policy.md) before deciding between the core DOMAIN-SET, the manual RULE-SET, and no new rule.

## Research the Whole Batch

For each domain:

1. Search current public information. Prefer the enterprise's official website, product documentation, privacy policy, security-response scope, endpoint or firewall documentation, and authoritative regulatory records.
2. Establish the operating entity and whether the service is a mainland China service. Separate verified facts from inference.
3. Determine whether the evidence supports only the observed host, a narrower parent, or the registrable service root. A brand relationship alone does not justify suffix expansion.
4. Check shared CDN, cloud, CNAME, and multi-tenant implications. Do not infer service ownership from IP geolocation or ASN ownership alone.
5. Check existing rules again after choosing the proposed scope. Report duplicates, broader coverage, conflicting files, and entries that should be removed if the proposal is accepted.

Complete the analysis for the entire supplied batch before requesting a decision.

## Present the Proposal

For every domain, report:

- normalized domain and current matching rule files;
- verified operator and China-enterprise conclusion;
- strongest evidence with direct links;
- confidence level and material uncertainty;
- proposed result: core suffix, exact manual rule, retained manual suffix, keep FINAL, or no addition;
- exact rule text and destination file when proposing a rule;
- entries made redundant by the proposal;
- shared-infrastructure or overmatching risk.

Then provide a compact batch table and ask one explicit question:

> 请确认：接受全部判定并授权我更新规则集、运行验证、提交并推送；或者指出需要调整的域名和判定。

This is an approval gate requested by the user. Before that answer, do not edit rule files, change SurgeObserver review state, commit, or push. Research, read-only inspection, and preparation of the concrete proposal are allowed.

## Apply an Approved Proposal

After explicit approval:

1. Apply only the approved decisions.
2. Use `.example.com` in `china_enterprise_domainset.txt` only when the evidence supports the root and all subdomains.
3. Use `DOMAIN,host.example.com` in `china_enterprise_manual_ruleset.txt` for observed exact hosts. Use `DOMAIN-SUFFIX` there only when evidence explicitly supports suffix scope but does not meet the core-set standard.
4. Preserve English group comments and deterministic ordering. Remove exact rules made redundant by an approved broader rule.
5. Update README source notes when adding a new core enterprise or materially changing its scope.
6. Update meaningful repository tests, then run:

```powershell
python -m unittest discover -s tests -v
python scripts/update_apple_rules.py --check
python scripts/update_google_rules.py --check
python scripts/update_microsoft_rules.py --check
git diff --check
```

7. Show the final diff and validation result. Commit and push only when that action was included in the user's approval. Report the resulting commit and verify local HEAD equals `origin/main`.

Never publish traffic logs, private hostnames, subscription URLs, credentials, policy names, or device identity data.
