#!/usr/bin/env python3
"""Normalize domains and report matching published Tailored-Rulesets entries."""

from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import json
import re
from pathlib import Path


LABEL_RE = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)\Z")
CORE_FILE = "china_enterprise_domainset.txt"
MANUAL_FILE = "china_enterprise_manual_ruleset.txt"


def normalize_domain(value: str) -> str:
    raw = value.strip().rstrip(".")
    if not raw or any(ch.isspace() for ch in raw) or any(ch in raw for ch in "/:@?#[]*,"):
        raise ValueError(f"not an exact hostname: {value!r}")
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        raise ValueError(f"IP literals are outside this workflow: {value!r}")
    try:
        normalized = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"invalid IDNA hostname: {value!r}") from exc
    if len(normalized) > 253 or any(not LABEL_RE.fullmatch(label) for label in normalized.split(".")):
        raise ValueError(f"invalid hostname: {value!r}")
    return normalized


def active_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip() and not line.lstrip().startswith(("#", ";"))
    ]


def suffix_match(domain: str, suffix: str) -> bool:
    normalized = suffix.lower().lstrip(".").rstrip(".")
    return domain == normalized or domain.endswith("." + normalized)


def rule_matches(domain: str, line: str, domainset: bool) -> bool:
    if domainset:
        return suffix_match(domain, line) if line.startswith(".") else domain == line.lower()
    fields = [field.strip() for field in line.split(",")]
    if len(fields) < 2:
        return False
    kind, value = fields[0], fields[1].lower().rstrip(".")
    if kind == "DOMAIN":
        return domain == value
    if kind == "DOMAIN-SUFFIX":
        return suffix_match(domain, value)
    if kind == "DOMAIN-WILDCARD":
        return fnmatch.fnmatchcase(domain, value)
    return False


def inspect_domain(repo: Path, domain: str) -> dict[str, object]:
    dist = repo / "dist"
    if not dist.is_dir():
        raise ValueError(f"repository has no dist directory: {repo}")
    matches: list[dict[str, str]] = []
    for path in sorted(dist.glob("*.txt"), key=lambda item: item.name):
        is_domainset = path.name.endswith("_domainset.txt")
        for line in active_lines(path):
            if rule_matches(domain, line, is_domainset):
                matches.append({"file": path.name, "rule": line})
    files = {match["file"] for match in matches}
    if CORE_FILE in files:
        classification = "core-domainset"
    elif MANUAL_FILE in files:
        classification = "enterprise-manual"
    elif matches:
        classification = "covered-elsewhere"
    else:
        classification = "unclassified"
    return {
        "domain": domain,
        "current_classification": classification,
        "matches": matches,
    }


def default_repo() -> Path:
    return Path(__file__).resolve().parents[4]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("domains", nargs="+")
    parser.add_argument("--repo", type=Path, default=default_repo())
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    try:
        domains = sorted({normalize_domain(value) for value in args.domains})
        data = [inspect_domain(args.repo.resolve(), domain) for domain in domains]
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    payload = {"schema_version": 1, "count": len(data), "data": data}
    print(json.dumps(payload, ensure_ascii=False, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
