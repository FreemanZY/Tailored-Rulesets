#!/usr/bin/env python3
"""Build deterministic Surge rules from the Microsoft 365 endpoint service."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = REPO_ROOT / "dist"
SOURCE_FILE = REPO_ROOT / "sources" / "microsoft_endpoints.json"
DOMAINSET_FILE = DIST_DIR / "microsoft_generated_domainset.txt"
RULESET_FILE = DIST_DIR / "microsoft_generated_ruleset.txt"

INSTANCES = ("Worldwide", "China", "USGovDoD", "USGovGCCHigh")
SERVICE_AREAS = {"Common", "Exchange", "SharePoint", "Skype"}
CATEGORIES = {"Optimize", "Allow", "Default"}
REQUIRED_RECORD_KEYS = {
    "id",
    "serviceArea",
    "serviceAreaDisplayName",
    "category",
    "expressRoute",
    "required",
}
OPTIONAL_RECORD_KEYS = {"urls", "ips", "tcpPorts", "udpPorts", "notes"}
ALLOWED_RECORD_KEYS = REQUIRED_RECORD_KEYS | OPTIONAL_RECORD_KEYS
PORTS_RE = re.compile(r"\d+(?:-\d+)?(?:,\s*\d+(?:-\d+)?)*\Z")
LABEL_RE = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)\Z")
SOURCE_BASE = "https://endpoints.office.com"
SOURCE_ID = "https://github.com/FreemanZY/Tailored-Rulesets/microsoft-endpoints"
CLIENT_REQUEST_ID = str(uuid.uuid5(uuid.NAMESPACE_URL, SOURCE_ID))
RETRY_DELAYS = (5, 15, 45)


class SourceDataError(ValueError):
    """The upstream or stored Microsoft data does not satisfy the contract."""


def _validate_hostname(hostname: str) -> str:
    try:
        ascii_name = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise SourceDataError(f"invalid IDNA hostname: {hostname!r}") from exc
    if len(ascii_name) > 253 or not ascii_name:
        raise SourceDataError(f"invalid hostname length: {hostname!r}")
    labels = ascii_name.split(".")
    if any(not LABEL_RE.fullmatch(label) for label in labels):
        raise SourceDataError(f"invalid hostname: {hostname!r}")
    return ascii_name


def classify_url(value: Any) -> tuple[str, str]:
    """Return (domainset|wildcard, normalized value) for one source URL."""
    if not isinstance(value, str):
        raise SourceDataError(f"URL entry must be a string: {value!r}")
    normalized = value.strip().lower().rstrip(".")
    if not normalized or any(ch.isspace() for ch in normalized):
        raise SourceDataError(f"invalid URL entry: {value!r}")
    if any(ch in normalized for ch in "/:@?#[]"):
        raise SourceDataError(f"URL entry is not a hostname pattern: {value!r}")

    if "*" not in normalized:
        return "domainset", _validate_hostname(normalized)

    if normalized.startswith("*.") and normalized.count("*") == 1:
        return "domainset", "." + _validate_hostname(normalized[2:])

    # Surge DOMAIN-WILDCARD is required for partial-label and middle wildcards.
    try:
        normalized.encode("ascii")
    except UnicodeEncodeError as exc:
        raise SourceDataError(f"wildcard hostname must be ASCII: {value!r}") from exc
    if "**" in normalized:
        raise SourceDataError(f"unsupported wildcard syntax: {value!r}")
    labels = normalized.split(".")
    if any(not label for label in labels):
        raise SourceDataError(f"invalid wildcard hostname: {value!r}")
    for label in labels:
        if "*" not in label:
            _validate_hostname(label)
            continue
        remainder = label.replace("*", "")
        if remainder and not LABEL_RE.fullmatch(remainder):
            raise SourceDataError(f"invalid wildcard label: {value!r}")
    return "wildcard", normalized


def validate_record(record: Any, instance: str) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise SourceDataError(f"{instance}: endpoint record is not an object")
    keys = set(record)
    missing = REQUIRED_RECORD_KEYS - keys
    unknown = keys - ALLOWED_RECORD_KEYS
    if missing or unknown:
        raise SourceDataError(
            f"{instance}: endpoint schema mismatch; missing={sorted(missing)}, "
            f"unknown={sorted(unknown)}"
        )
    if not isinstance(record["id"], int) or isinstance(record["id"], bool):
        raise SourceDataError(f"{instance}: endpoint id must be an integer")
    if record["serviceArea"] not in SERVICE_AREAS:
        raise SourceDataError(f"{instance}: unknown serviceArea {record['serviceArea']!r}")
    if not isinstance(record["serviceAreaDisplayName"], str):
        raise SourceDataError(f"{instance}: serviceAreaDisplayName must be a string")
    if record["category"] not in CATEGORIES:
        raise SourceDataError(f"{instance}: unknown category {record['category']!r}")
    for key in ("expressRoute", "required"):
        if not isinstance(record[key], bool):
            raise SourceDataError(f"{instance}: {key} must be Boolean")
    for key in ("urls", "ips"):
        if key in record:
            if not isinstance(record[key], list) or not record[key]:
                raise SourceDataError(f"{instance}: {key} must be a non-empty array")
            if any(not isinstance(item, str) or not item.strip() for item in record[key]):
                raise SourceDataError(f"{instance}: {key} contains an invalid item")
    for key in ("tcpPorts", "udpPorts"):
        if key in record and (
            not isinstance(record[key], str)
            or (record[key] and not PORTS_RE.fullmatch(record[key]))
        ):
            raise SourceDataError(f"{instance}: invalid {key} value {record[key]!r}")
    if "notes" in record and not isinstance(record["notes"], str):
        raise SourceDataError(f"{instance}: notes must be a string")
    if "urls" not in record and "ips" not in record:
        raise SourceDataError(f"{instance}: endpoint {record['id']} has no URLs or IPs")

    # Sorting list fields prevents upstream ordering changes from causing churn.
    normalized = dict(record)
    for key in ("urls", "ips"):
        if key in normalized:
            normalized[key] = sorted(set(normalized[key]), key=str.casefold)
    return normalized


def normalize_records(payload: Any, instance: str) -> list[dict[str, Any]]:
    if not isinstance(payload, list) or not payload:
        raise SourceDataError(f"{instance}: endpoint response must be a non-empty array")
    records = [validate_record(record, instance) for record in payload]
    ids = [record["id"] for record in records]
    if len(ids) != len(set(ids)):
        raise SourceDataError(f"{instance}: duplicate endpoint id")
    return sorted(records, key=lambda record: record["id"])


def build_manifest(versions: dict[str, str], payloads: dict[str, Any]) -> dict[str, Any]:
    if set(versions) != set(INSTANCES) or set(payloads) != set(INSTANCES):
        raise SourceDataError("manifest inputs must contain exactly the four target instances")
    instances: dict[str, Any] = {}
    for instance in INSTANCES:
        version = versions[instance]
        if not isinstance(version, str) or not re.fullmatch(r"\d{10}", version):
            raise SourceDataError(f"{instance}: invalid version {version!r}")
        instances[instance] = {
            "version": version,
            "records": normalize_records(payloads[instance], instance),
        }
    return {
        "schema_version": 1,
        "source": SOURCE_BASE,
        "instances": instances,
    }


def validate_manifest(manifest: Any) -> dict[str, Any]:
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version",
        "source",
        "instances",
    }:
        raise SourceDataError("stored manifest has an unsupported top-level schema")
    if manifest["schema_version"] != 1 or manifest["source"] != SOURCE_BASE:
        raise SourceDataError("stored manifest schema version or source is invalid")
    instances = manifest["instances"]
    if not isinstance(instances, dict) or set(instances) != set(INSTANCES):
        raise SourceDataError("stored manifest must contain exactly the four target instances")
    payloads: dict[str, Any] = {}
    versions: dict[str, str] = {}
    for instance in INSTANCES:
        block = instances[instance]
        if not isinstance(block, dict) or set(block) != {"version", "records"}:
            raise SourceDataError(f"{instance}: invalid stored instance block")
        versions[instance] = block["version"]
        payloads[instance] = block["records"]
    return build_manifest(versions, payloads)


def manifest_versions(manifest: dict[str, Any]) -> dict[str, str]:
    return {
        instance: manifest["instances"][instance]["version"] for instance in INSTANCES
    }


def _version_header(manifest: dict[str, Any]) -> str:
    return ", ".join(
        f"{instance}={manifest['instances'][instance]['version']}"
        for instance in INSTANCES
    )


def render_outputs(manifest: dict[str, Any]) -> tuple[str, str]:
    manifest = validate_manifest(manifest)
    domains: set[str] = set()
    wildcards: set[str] = set()
    ipv4: set[ipaddress.IPv4Network] = set()
    ipv6: set[ipaddress.IPv6Network] = set()

    for instance in INSTANCES:
        for record in manifest["instances"][instance]["records"]:
            for source_url in record.get("urls", []):
                kind, value = classify_url(source_url)
                (domains if kind == "domainset" else wildcards).add(value)
            for source_ip in record.get("ips", []):
                try:
                    network = ipaddress.ip_network(source_ip, strict=True)
                except ValueError as exc:
                    raise SourceDataError(
                        f"{instance}: invalid or non-canonical CIDR {source_ip!r}"
                    ) from exc
                (ipv4 if network.version == 4 else ipv6).add(network)

    versions = _version_header(manifest)
    domain_lines = [
        "# GENERATED DOMAIN-SET: Microsoft 365 endpoints; do not edit manually.",
        f"# Source versions: {versions}",
        "# Exact source names stay exact; source *.example.com becomes .example.com.",
        *sorted(domains),
    ]
    rule_lines = [
        "# GENERATED RULE-SET: Microsoft 365 complex wildcards and IP ranges.",
        f"# Source versions: {versions}",
        "# Policies belong in the consuming Surge profile.",
        *(f"DOMAIN-WILDCARD,{value}" for value in sorted(wildcards)),
        *(
            f"IP-CIDR,{network},no-resolve"
            for network in sorted(ipv4, key=lambda item: (int(item.network_address), item.prefixlen))
        ),
        *(
            f"IP-CIDR6,{network},no-resolve"
            for network in sorted(ipv6, key=lambda item: (int(item.network_address), item.prefixlen))
        ),
    ]
    return "\n".join(domain_lines) + "\n", "\n".join(rule_lines) + "\n"


def serialize_manifest(manifest: dict[str, Any]) -> str:
    return json.dumps(validate_manifest(manifest), indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def _request_json(url: str) -> Any:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "Tailored-Rulesets Microsoft endpoint updater",
        },
    )
    for attempt in range(len(RETRY_DELAYS) + 1):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                if response.status != 200:
                    raise SourceDataError(f"unexpected HTTP status {response.status} for {url}")
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise SourceDataError(
                    "Microsoft endpoint service returned 429; wait for the next run"
                ) from exc
            retryable = 500 <= exc.code <= 599
            error: Exception = exc
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            retryable = True
            error = exc
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SourceDataError(f"invalid JSON response from {url}") from exc
        if not retryable or attempt == len(RETRY_DELAYS):
            raise SourceDataError(f"request failed for {url}: {error}") from error
        time.sleep(RETRY_DELAYS[attempt])
    raise AssertionError("unreachable")


def fetch_versions() -> dict[str, str]:
    query = urllib.parse.urlencode({"clientRequestId": CLIENT_REQUEST_ID})
    payload = _request_json(f"{SOURCE_BASE}/version?{query}")
    if not isinstance(payload, list):
        raise SourceDataError("version response must be an array")
    selected: dict[str, str] = {}
    for item in payload:
        if not isinstance(item, dict):
            raise SourceDataError("version response contains a non-object item")
        instance = item.get("instance")
        if instance not in INSTANCES:
            continue
        if instance in selected:
            raise SourceDataError(f"duplicate version for {instance}")
        version = item.get("latest")
        if not isinstance(version, str) or not re.fullmatch(r"\d{10}", version):
            raise SourceDataError(f"invalid version for {instance}: {version!r}")
        selected[instance] = version
    missing = set(INSTANCES) - set(selected)
    if missing:
        raise SourceDataError(f"version response is missing {sorted(missing)}")
    return selected


def fetch_payloads() -> dict[str, Any]:
    query = urllib.parse.urlencode({"clientRequestId": CLIENT_REQUEST_ID})
    return {
        instance: _request_json(f"{SOURCE_BASE}/endpoints/{instance}?{query}")
        for instance in INSTANCES
    }


def _read_manifest_if_valid() -> dict[str, Any] | None:
    if not SOURCE_FILE.exists():
        return None
    try:
        return validate_manifest(json.loads(SOURCE_FILE.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, SourceDataError) as exc:
        print(f"Stored source manifest will be refreshed: {exc}", file=sys.stderr)
        return None


def _atomic_replace_many(contents: dict[Path, str]) -> list[Path]:
    changed = [path for path, text in contents.items() if not path.exists() or path.read_text(encoding="utf-8") != text]
    if not changed:
        return []
    staged: dict[Path, Path] = {}
    try:
        for path in changed:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
            temp_path = Path(temp_name)
            staged[path] = temp_path
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(contents[path])
        for path in changed:
            os.replace(staged[path], path)
    finally:
        for temp_path in staged.values():
            temp_path.unlink(missing_ok=True)
    return changed


def update() -> list[Path]:
    versions = fetch_versions()
    manifest = _read_manifest_if_valid()
    if manifest is None or manifest_versions(manifest) != versions:
        manifest = build_manifest(versions, fetch_payloads())
        print("Microsoft source version changed; refreshed all four instances.")
    else:
        print("Microsoft source versions are unchanged; rebuilding from stored source.")
    domainset, ruleset = render_outputs(manifest)
    changed = _atomic_replace_many(
        {
            SOURCE_FILE: serialize_manifest(manifest),
            DOMAINSET_FILE: domainset,
            RULESET_FILE: ruleset,
        }
    )
    if changed:
        print("Updated: " + ", ".join(str(path.relative_to(REPO_ROOT)) for path in changed))
    else:
        print("All Microsoft generated files are current.")
    return changed


def check() -> None:
    if not SOURCE_FILE.exists():
        raise SourceDataError(f"missing source manifest: {SOURCE_FILE}")
    manifest = validate_manifest(json.loads(SOURCE_FILE.read_text(encoding="utf-8")))
    domainset, ruleset = render_outputs(manifest)
    expected = {DOMAINSET_FILE: domainset, RULESET_FILE: ruleset}
    stale = [
        path.relative_to(REPO_ROOT)
        for path, text in expected.items()
        if not path.exists() or path.read_text(encoding="utf-8") != text
    ]
    if stale:
        raise SourceDataError(f"generated outputs are stale: {', '.join(map(str, stale))}")
    print(f"PASS: Microsoft source and outputs match ({_version_header(manifest)}).")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate committed source and outputs without network access or writes",
    )
    args = parser.parse_args()
    try:
        check() if args.check else update()
    except (OSError, SourceDataError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
