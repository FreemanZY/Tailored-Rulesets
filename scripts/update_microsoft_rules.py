#!/usr/bin/env python3
"""Build deterministic Surge rules from Microsoft 365 and Power Apps sources."""

from __future__ import annotations

import argparse
import hashlib
import html
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
POWER_APPS_PAGE_URL = "https://learn.microsoft.com/en-us/power-apps/limits-and-config"
POWER_APPS_CONTENT_URL = (
    "https://raw.githubusercontent.com/MicrosoftDocs/powerapps-docs/"
    "main/powerapps-docs/limits-and-config.md"
)
SOURCE_ID = "https://github.com/FreemanZY/Tailored-Rulesets/microsoft-endpoints"
CLIENT_REQUEST_ID = str(uuid.uuid5(uuid.NAMESPACE_URL, SOURCE_ID))
RETRY_DELAYS = (5, 15, 45)
POWER_APPS_LOCAL_TARGETS = {"127.0.0.1", "localhost"}
POWER_APPS_REQUIRED_DOMAINS = {
    "*.events.data.microsoft.com",
    "*.powerapps.com",
    "api.bap.microsoft.com",
    "arc.msn.com",
    "*.crm.dynamics.com",
}
HTML_BREAK_RE = re.compile(r"<br\s*/?>", re.IGNORECASE)
HTML_TAG_RE = re.compile(r"<[^>]+>")


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


def _plain_markdown_cell(value: str) -> str:
    value = HTML_BREAK_RE.sub(" ", value)
    value = re.sub(r"</?li>", " ", value, flags=re.IGNORECASE)
    value = HTML_TAG_RE.sub(" ", value)
    value = re.sub(r"\[([^]]+)]\([^)]+\)", r"\1", value)
    return " ".join(html.unescape(value).split())


def _split_power_apps_domains(value: str) -> list[str]:
    value = HTML_BREAK_RE.sub("\n", value)
    value = HTML_TAG_RE.sub("", value)
    return [
        html.unescape(item).strip().replace(r"\*", "*")
        for item in value.splitlines()
        if item.strip()
    ]


def _expand_power_apps_domains(domain_cell: str, uses_cell: str) -> tuple[list[str], list[str]]:
    source_domains = _split_power_apps_domains(domain_cell)
    crm_templates = {
        "http://*.crm#.dynamics.com and https://*.crm#.dynamics.com",
    }
    if len(source_domains) == 1 and source_domains[0] in crm_templates:
        region_numbers: set[str] = set()
        saw_no_number = False
        list_items = re.findall(r"<li>(.*?)</li>", uses_cell, flags=re.IGNORECASE)
        if not list_items:
            raise SourceDataError("Power Apps CRM template has no region list")
        for item in list_items:
            text = _plain_markdown_cell(item)
            if ":" not in text:
                raise SourceDataError(f"Power Apps CRM region item is malformed: {text!r}")
            value = text.split(":", 1)[1].strip().lower()
            if value == "no number":
                saw_no_number = True
                continue
            numbers = re.findall(r"\b\d{1,2}\b", value)
            if not numbers:
                raise SourceDataError(f"Power Apps CRM region has no number: {text!r}")
            region_numbers.update(numbers)
        if not saw_no_number:
            raise SourceDataError("Power Apps CRM region list omits the no-number endpoint")
        expanded = ["*.crm.dynamics.com"] + [
            f"*.crm{number}.dynamics.com"
            for number in sorted(region_numbers, key=int)
        ]
        return source_domains, expanded

    normalized: list[str] = []
    for value in source_domains:
        if value in POWER_APPS_LOCAL_TARGETS:
            continue
        if "://" in value:
            raise SourceDataError(f"unsupported Power Apps URL template: {value!r}")
        classify_url(value)
        normalized.append(value.lower().rstrip("."))
    return source_domains, sorted(set(normalized))


def build_power_apps_source(markdown: str) -> dict[str, Any]:
    if not isinstance(markdown, str) or not markdown.strip():
        raise SourceDataError("Power Apps source must be non-empty text")
    date_match = re.search(r"(?m)^ms\.date:\s*([^\s]+)\s*$", markdown)
    if not date_match:
        raise SourceDataError("Power Apps source is missing ms.date")
    document_date = date_match.group(1)
    if not re.fullmatch(r"\d{2}/\d{2}/\d{4}", document_date):
        raise SourceDataError(f"invalid Power Apps document date: {document_date!r}")

    start_marker = "## Required services"
    end_marker = "## Deprecated endpoints"
    if markdown.count(start_marker) != 1 or markdown.count(end_marker) != 1:
        raise SourceDataError("Power Apps required-services section markers changed")
    section = markdown.split(start_marker, 1)[1].split(end_marker, 1)[0]
    lines = section.splitlines()
    header_index = next(
        (index for index, line in enumerate(lines) if re.fullmatch(r"\|\s*Domains\s*\|\s*Protocols\s*\|\s*Uses\s*\|", line)),
        None,
    )
    if header_index is None or header_index + 1 >= len(lines):
        raise SourceDataError("Power Apps required-services table header changed")
    if not re.fullmatch(r"\|\s*-+\s*\|\s*-+\s*\|\s*-+\s*\|", lines[header_index + 1]):
        raise SourceDataError("Power Apps required-services table delimiter changed")

    records: list[dict[str, Any]] = []
    excluded_local_targets: set[str] = set()
    for line in lines[header_index + 2 :]:
        if not line.startswith("|"):
            if records:
                break
            continue
        cells = line[1:-1].split("|") if line.endswith("|") else line[1:].split("|")
        if len(cells) != 3:
            raise SourceDataError(f"Power Apps table row has {len(cells)} cells")
        domain_cell, protocol_cell, uses_cell = (cell.strip() for cell in cells)
        source_domains, normalized_domains = _expand_power_apps_domains(domain_cell, uses_cell)
        excluded = sorted(set(source_domains) & POWER_APPS_LOCAL_TARGETS)
        excluded_local_targets.update(excluded)
        protocol_match = re.match(r"(?i)^(https|http|wss)\b", _plain_markdown_cell(protocol_cell))
        if not protocol_match:
            raise SourceDataError(f"Power Apps row has invalid protocol: {protocol_cell!r}")
        records.append(
            {
                "source_domains": source_domains,
                "normalized_domains": normalized_domains,
                "excluded_targets": excluded,
                "protocol": protocol_match.group(1).lower(),
                "uses": _plain_markdown_cell(uses_cell),
            }
        )

    published = {
        domain
        for record in records
        for domain in record["normalized_domains"]
    }
    missing = POWER_APPS_REQUIRED_DOMAINS - published
    if missing:
        raise SourceDataError(f"Power Apps table is missing required domains: {sorted(missing)}")
    if excluded_local_targets != POWER_APPS_LOCAL_TARGETS:
        raise SourceDataError("Power Apps local-only targets changed")
    if len(records) < 25:
        raise SourceDataError(f"Power Apps table appears truncated: only {len(records)} rows")

    semantic = {
        "records": records,
        "excluded_local_targets": sorted(excluded_local_targets),
    }
    semantic_hash = hashlib.sha256(
        json.dumps(semantic, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "page_url": POWER_APPS_PAGE_URL,
        "content_url": POWER_APPS_CONTENT_URL,
        "document_date": document_date,
        "semantic_hash": semantic_hash,
        **semantic,
    }


def validate_power_apps_source(source: Any) -> dict[str, Any]:
    expected_keys = {
        "page_url",
        "content_url",
        "document_date",
        "semantic_hash",
        "records",
        "excluded_local_targets",
    }
    if not isinstance(source, dict) or set(source) != expected_keys:
        raise SourceDataError("stored Power Apps source has an unsupported schema")
    if source["page_url"] != POWER_APPS_PAGE_URL or source["content_url"] != POWER_APPS_CONTENT_URL:
        raise SourceDataError("stored Power Apps source URLs are invalid")
    if not re.fullmatch(r"\d{2}/\d{2}/\d{4}", source.get("document_date", "")):
        raise SourceDataError("stored Power Apps document date is invalid")
    if not isinstance(source["records"], list) or len(source["records"]) < 25:
        raise SourceDataError("stored Power Apps records are missing or truncated")
    if source["excluded_local_targets"] != sorted(POWER_APPS_LOCAL_TARGETS):
        raise SourceDataError("stored Power Apps local-only targets changed")

    for record in source["records"]:
        if not isinstance(record, dict) or set(record) != {
            "source_domains",
            "normalized_domains",
            "excluded_targets",
            "protocol",
            "uses",
        }:
            raise SourceDataError("stored Power Apps record schema changed")
        if not isinstance(record["source_domains"], list) or not record["source_domains"]:
            raise SourceDataError("stored Power Apps record has no source domains")
        if not isinstance(record["normalized_domains"], list):
            raise SourceDataError("stored Power Apps normalized domains are invalid")
        for value in record["normalized_domains"]:
            classify_url(value)
        if record["protocol"] not in {"http", "https", "wss"}:
            raise SourceDataError("stored Power Apps protocol is invalid")
        if not isinstance(record["uses"], str):
            raise SourceDataError("stored Power Apps usage is invalid")
        if not isinstance(record["excluded_targets"], list):
            raise SourceDataError("stored Power Apps exclusions are invalid")

    semantic = {
        "records": source["records"],
        "excluded_local_targets": source["excluded_local_targets"],
    }
    expected_hash = hashlib.sha256(
        json.dumps(semantic, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if source["semantic_hash"] != expected_hash:
        raise SourceDataError("stored Power Apps semantic hash does not match its records")
    published = {
        domain
        for record in source["records"]
        for domain in record["normalized_domains"]
    }
    missing = POWER_APPS_REQUIRED_DOMAINS - published
    if missing:
        raise SourceDataError(f"stored Power Apps source is missing {sorted(missing)}")
    return source


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


def build_manifest(
    versions: dict[str, str],
    payloads: dict[str, Any],
    power_apps: dict[str, Any],
) -> dict[str, Any]:
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
        "schema_version": 2,
        "source": SOURCE_BASE,
        "instances": instances,
        "power_apps": validate_power_apps_source(power_apps),
    }


def validate_manifest(manifest: Any) -> dict[str, Any]:
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version",
        "source",
        "instances",
        "power_apps",
    }:
        raise SourceDataError("stored manifest has an unsupported top-level schema")
    if manifest["schema_version"] != 2 or manifest["source"] != SOURCE_BASE:
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
    return build_manifest(versions, payloads, validate_power_apps_source(manifest["power_apps"]))


def manifest_versions(manifest: dict[str, Any]) -> dict[str, str]:
    return {
        instance: manifest["instances"][instance]["version"] for instance in INSTANCES
    }


def _version_header(manifest: dict[str, Any]) -> str:
    m365_versions = ", ".join(
        f"{instance}={manifest['instances'][instance]['version']}"
        for instance in INSTANCES
    )
    return f"{m365_versions}, PowerApps={manifest['power_apps']['semantic_hash'][:12]}"


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

    for record in manifest["power_apps"]["records"]:
        for source_url in record["normalized_domains"]:
            kind, value = classify_url(source_url)
            (domains if kind == "domainset" else wildcards).add(value)

    versions = _version_header(manifest)
    domain_lines = [
        "# GENERATED DOMAIN-SET: Microsoft 365 and Power Apps endpoints; do not edit manually.",
        f"# Source versions: {versions}",
        "# Exact source names stay exact; source *.example.com becomes .example.com.",
        *sorted(domains),
    ]
    rule_lines = [
        "# GENERATED RULE-SET: Microsoft 365 and Power Apps complex wildcards and IP ranges.",
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


def _request_text(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "text/plain, text/markdown;q=0.9, */*;q=0.1",
            "User-Agent": "Tailored-Rulesets Microsoft endpoint updater",
        },
    )
    for attempt in range(len(RETRY_DELAYS) + 1):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                if response.status != 200:
                    raise SourceDataError(f"unexpected HTTP status {response.status} for {url}")
                return response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise SourceDataError(
                    "Microsoft documentation source returned 429; wait for the next run"
                ) from exc
            retryable = 500 <= exc.code <= 599
            error: Exception = exc
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            retryable = True
            error = exc
        except UnicodeDecodeError as exc:
            raise SourceDataError(f"invalid UTF-8 response from {url}") from exc
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


def fetch_power_apps_source() -> dict[str, Any]:
    return build_power_apps_source(_request_text(POWER_APPS_CONTENT_URL))


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
    power_apps = fetch_power_apps_source()
    stored_manifest = _read_manifest_if_valid()
    if stored_manifest is None or manifest_versions(stored_manifest) != versions:
        payloads = fetch_payloads()
        print("Microsoft 365 source version changed; refreshed all four instances.")
    else:
        payloads = {
            instance: stored_manifest["instances"][instance]["records"]
            for instance in INSTANCES
        }
        print("Microsoft 365 source versions are unchanged; reused stored records.")
    if (
        stored_manifest is not None
        and stored_manifest["power_apps"]["semantic_hash"] == power_apps["semantic_hash"]
    ):
        power_apps = stored_manifest["power_apps"]
        print("Power Apps endpoint semantics are unchanged; preserved stored metadata.")
    else:
        print("Power Apps endpoint semantics changed; refreshed the stored source.")
    manifest = build_manifest(versions, payloads, power_apps)
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
