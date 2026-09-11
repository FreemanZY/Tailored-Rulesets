#!/usr/bin/env python3
"""Build deterministic Surge rules from Apple's enterprise network article."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = REPO_ROOT / "dist"
SOURCE_FILE = REPO_ROOT / "sources" / "apple_enterprise_networks.json"
DOMAINSET_FILE = DIST_DIR / "apple_generated_domainset.txt"
RULESET_FILE = DIST_DIR / "apple_generated_ip_ruleset.txt"

SOURCE_URL = "https://support.apple.com/en-us/101555"
EXPECTED_TITLE = "Use Apple products on enterprise networks"
EXPECTED_HEADERS = (
    "Hosts",
    "Ports",
    "Protocol",
    "OS",
    "Description",
    "Supports proxies",
)
REQUIRED_SECTION_IDS = {
    "devicesetup",
    "devicemanagement",
    "software",
    "appscontent",
    "icloud",
    "firewalls",
    "recentchanges",
}
MIN_TABLES = 15
MIN_ROWS = 100
MIN_UNIQUE_HOSTS = 100
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
RETRY_DELAYS = (5, 15, 45)
LABEL_RE = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)\Z")
PORTS_RE = re.compile(r"\d+(?:\s*,\s*\d+)*\Z")
CIDR_TOKEN_RE = re.compile(
    r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f:.]+)/(?:\d{1,3})(?!\d)"
)
WILDCARD_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9*.-])\*\.(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+\b"
)
VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}


class SourceDataError(ValueError):
    """The upstream or stored Apple data does not satisfy the contract."""


def _clean_text(parts: list[str]) -> str:
    return " ".join(" ".join(parts).replace("\xa0", " ").split())


def _validate_hostname(hostname: str) -> str:
    try:
        ascii_name = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise SourceDataError(f"invalid IDNA hostname: {hostname!r}") from exc
    if not ascii_name or len(ascii_name) > 253:
        raise SourceDataError(f"invalid hostname length: {hostname!r}")
    if any(not LABEL_RE.fullmatch(label) for label in ascii_name.split(".")):
        raise SourceDataError(f"invalid hostname: {hostname!r}")
    return ascii_name


def classify_host(value: Any) -> tuple[str, str]:
    """Return (source pattern, DOMAIN-SET value) for one Apple host."""
    if not isinstance(value, str):
        raise SourceDataError(f"host must be a string: {value!r}")
    normalized = value.strip().lower().rstrip(".")
    if not normalized or any(ch.isspace() for ch in normalized):
        raise SourceDataError(f"invalid host: {value!r}")
    if any(ch in normalized for ch in "/:@?#[]"):
        raise SourceDataError(f"host is not a hostname pattern: {value!r}")
    if "*" not in normalized:
        exact = _validate_hostname(normalized)
        return exact, exact
    if normalized.startswith("*.") and normalized.count("*") == 1:
        suffix = _validate_hostname(normalized[2:])
        return f"*.{suffix}", f".{suffix}"
    raise SourceDataError(
        f"unsupported Apple wildcard {value!r}; review before changing output format"
    )


def _parse_ports(value: str) -> list[int]:
    if not PORTS_RE.fullmatch(value):
        raise SourceDataError(f"invalid ports value: {value!r}")
    ports = [int(item.strip()) for item in value.split(",")]
    if any(port < 1 or port > 65535 for port in ports):
        raise SourceDataError(f"port outside 1-65535: {value!r}")
    if len(ports) != len(set(ports)):
        raise SourceDataError(f"duplicate port: {value!r}")
    return ports


def _parse_protocols(value: str) -> list[str]:
    protocols = [item.strip().upper() for item in re.split(r"[,/]", value)]
    if not protocols or any(item not in {"TCP", "UDP", "SSH"} for item in protocols):
        raise SourceDataError(f"unknown protocol value: {value!r}")
    if len(protocols) != len(set(protocols)):
        raise SourceDataError(f"duplicate protocol: {value!r}")
    return protocols


class AppleArticleParser(HTMLParser):
    """Parse the server-rendered article while rejecting silent table drift."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.canonical_url: str | None = None
        self.title: str | None = None
        self.published_date: str | None = None
        self.section_ids: set[str] = set()
        self.tables: list[dict[str, Any]] = []
        self.firewall_parts: list[str] = []
        self.recent_changes: list[str] = []

        self._sections_depth = 0
        self._saw_sections_end = False
        self._saw_html_end = False
        self._heading_tag: str | None = None
        self._heading_id: str | None = None
        self._heading_parts: list[str] = []
        self._current_h2_id: str | None = None
        self._current_h2: str | None = None
        self._current_h3: str | None = None
        self._h1_parts: list[str] | None = None
        self._time_parts: list[str] | None = None
        self._time_value: str | None = None
        self._recent_li_parts: list[str] | None = None

        self._table: dict[str, Any] | None = None
        self._row: list[dict[str, Any]] | None = None
        self._cell_tag: str | None = None
        self._cell_parts: list[str] = []
        self._cell_links: list[dict[str, str]] = []
        self._link_href: str | None = None
        self._link_parts: list[str] | None = None

    @staticmethod
    def _attrs(attrs: list[tuple[str, str | None]]) -> dict[str, str | None]:
        return dict(attrs)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = self._attrs(attrs)
        if tag == "link" and values.get("rel") == "canonical":
            self.canonical_url = values.get("href")
        if tag == "html":
            self._saw_html_end = False
        if values.get("id") == "sections":
            if self._sections_depth:
                raise SourceDataError("nested #sections containers")
            self._sections_depth = 1
        elif self._sections_depth and tag not in VOID_TAGS:
            self._sections_depth += 1

        if tag == "h1":
            self._h1_parts = []
        if tag in {"h2", "h3"} and self._sections_depth:
            self._heading_tag = tag
            self._heading_id = values.get("id")
            self._heading_parts = []
        # Apple currently emits a malformed unquoted dateTime attribute, so the
        # visible value is the reliable contract for the article's only <time>.
        if tag == "time":
            self._time_parts = []
            self._time_value = values.get("datetime") or values.get("dateTime")
        if tag == "li" and self._current_h2_id == "recentchanges":
            self._recent_li_parts = []

        if tag == "table" and self._sections_depth:
            if self._table is not None:
                raise SourceDataError("nested tables are unsupported")
            self._table = {
                "section_id": self._current_h2_id,
                "section": self._current_h2,
                "subsection": self._current_h3,
                "rows": [],
            }
        elif tag == "tr" and self._table is not None:
            if self._row is not None:
                raise SourceDataError("nested table rows are unsupported")
            self._row = []
        elif tag in {"th", "td"} and self._row is not None:
            if self._cell_tag is not None:
                raise SourceDataError("nested table cells are unsupported")
            if values.get("colspan", "1") != "1" or values.get("rowspan", "1") != "1":
                raise SourceDataError("merged Apple table cells require parser review")
            self._cell_tag = tag
            self._cell_parts = []
            self._cell_links = []
        elif tag == "a" and self._cell_tag is not None:
            self._link_href = values.get("href") or ""
            self._link_parts = []

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in VOID_TAGS:
            self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if self._h1_parts is not None:
            self._h1_parts.append(data)
        if self._heading_tag is not None:
            self._heading_parts.append(data)
        if self._time_parts is not None:
            self._time_parts.append(data)
        if self._current_h2_id == "firewalls" and self._heading_tag is None:
            self.firewall_parts.append(data)
        if self._recent_li_parts is not None:
            self._recent_li_parts.append(data)
        if self._cell_tag is not None:
            self._cell_parts.append(data)
        if self._link_parts is not None:
            self._link_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._link_parts is not None:
            self._cell_links.append(
                {"text": _clean_text(self._link_parts), "href": self._link_href or ""}
            )
            self._link_href = None
            self._link_parts = None
        elif tag == self._cell_tag:
            assert self._row is not None
            self._row.append(
                {
                    "kind": self._cell_tag,
                    "text": _clean_text(self._cell_parts),
                    "links": self._cell_links,
                }
            )
            self._cell_tag = None
            self._cell_parts = []
            self._cell_links = []
        elif tag == "tr" and self._row is not None:
            assert self._table is not None
            self._table["rows"].append(self._row)
            self._row = None
        elif tag == "table" and self._table is not None:
            self.tables.append(self._table)
            self._table = None

        if tag == self._heading_tag:
            heading = _clean_text(self._heading_parts)
            if not heading:
                raise SourceDataError(f"empty {tag} heading")
            if tag == "h2":
                if not self._heading_id:
                    raise SourceDataError(f"article h2 lacks id: {heading!r}")
                self._current_h2_id = self._heading_id
                self._current_h2 = heading
                self._current_h3 = None
                self.section_ids.add(self._heading_id)
            else:
                self._current_h3 = heading
            self._heading_tag = None
            self._heading_id = None
            self._heading_parts = []
        if tag == "h1" and self._h1_parts is not None:
            self.title = _clean_text(self._h1_parts)
            self._h1_parts = None
        if tag == "time" and self._time_parts is not None:
            visible = _clean_text(self._time_parts)
            self.published_date = visible or self._time_value
            self._time_parts = None
            self._time_value = None
        if tag == "li" and self._recent_li_parts is not None:
            value = _clean_text(self._recent_li_parts)
            if value:
                self.recent_changes.append(value)
            self._recent_li_parts = None

        if self._sections_depth and tag not in VOID_TAGS:
            self._sections_depth -= 1
            if not self._sections_depth:
                self._saw_sections_end = True
        if tag == "html":
            self._saw_html_end = True


def _normalize_published_date(value: str | None) -> str:
    if not value:
        raise SourceDataError("missing Published Date")
    for pattern in ("%B %d, %Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(value.strip(), pattern).date().isoformat()
        except ValueError:
            pass
    raise SourceDataError(f"unsupported Published Date: {value!r}")


def parse_article(html: str) -> dict[str, Any]:
    parser = AppleArticleParser()
    try:
        parser.feed(html)
        parser.close()
    except (AssertionError, SourceDataError) as exc:
        raise SourceDataError(f"invalid Apple article HTML: {exc}") from exc

    if not parser._saw_sections_end or not parser._saw_html_end:
        raise SourceDataError("Apple article appears truncated")
    if parser.canonical_url != SOURCE_URL:
        raise SourceDataError(f"unexpected canonical URL: {parser.canonical_url!r}")
    if not parser.title or EXPECTED_TITLE not in parser.title:
        raise SourceDataError(f"unexpected article title: {parser.title!r}")
    missing_sections = REQUIRED_SECTION_IDS - parser.section_ids
    if missing_sections:
        raise SourceDataError(f"missing required sections: {sorted(missing_sections)}")
    if len(parser.tables) < MIN_TABLES:
        raise SourceDataError(f"too few endpoint tables: {len(parser.tables)}")

    endpoint_rows: list[dict[str, Any]] = []
    for table_index, table in enumerate(parser.tables, start=1):
        rows = table["rows"]
        if len(rows) < 2:
            raise SourceDataError(f"table {table_index} has no endpoint rows")
        header = rows[0]
        if any(cell["kind"] != "th" for cell in header):
            raise SourceDataError(f"table {table_index} does not start with headers")
        header_values = tuple(cell["text"] for cell in header)
        if header_values and header_values[1] == "Port":
            header_values = (header_values[0], "Ports", *header_values[2:])
        if header_values != EXPECTED_HEADERS:
            raise SourceDataError(
                f"table {table_index} header mismatch: {header_values!r}"
            )
        for row_index, row in enumerate(rows[1:], start=1):
            if len(row) != 6 or any(cell["kind"] != "td" for cell in row):
                raise SourceDataError(
                    f"table {table_index} row {row_index} is not six data cells"
                )
            values = [cell["text"] for cell in row]
            source_host, _ = classify_host(values[0])
            endpoint_rows.append(
                {
                    "table_index": table_index,
                    "row_index": row_index,
                    "section_id": table["section_id"],
                    "section": table["section"],
                    "subsection": table["subsection"],
                    "host": source_host,
                    "ports": _parse_ports(values[1]),
                    "protocols": _parse_protocols(values[2]),
                    "os": values[3],
                    "description": values[4],
                    "supports_proxies": values[5],
                    "links": [
                        {"field": EXPECTED_HEADERS[index], **link}
                        for index, cell in enumerate(row)
                        for link in cell["links"]
                    ],
                }
            )

    unique_hosts = {row["host"] for row in endpoint_rows}
    if len(endpoint_rows) < MIN_ROWS or len(unique_hosts) < MIN_UNIQUE_HOSTS:
        raise SourceDataError(
            f"endpoint extraction is unexpectedly small: rows={len(endpoint_rows)}, "
            f"unique_hosts={len(unique_hosts)}"
        )

    firewall_text = _clean_text(parser.firewall_parts)
    firewall_patterns = sorted(set(WILDCARD_TOKEN_RE.findall(firewall_text)))
    if "*.apple.com" not in firewall_patterns:
        raise SourceDataError("Firewalls section no longer contains *.apple.com")
    for pattern in firewall_patterns:
        classify_host(pattern)
    cidr_tokens = CIDR_TOKEN_RE.findall(firewall_text)
    if not cidr_tokens:
        raise SourceDataError("Firewalls section has no IP ranges")
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for value in cidr_tokens:
        try:
            networks.append(ipaddress.ip_network(value, strict=True))
        except ValueError as exc:
            raise SourceDataError(f"invalid or non-canonical Apple CIDR: {value!r}") from exc
    if len(networks) != len(set(networks)):
        raise SourceDataError("duplicate IP range in Firewalls section")
    if not any(network.version == 4 for network in networks) or not any(
        network.version == 6 for network in networks
    ):
        raise SourceDataError("Firewalls section must contain IPv4 and IPv6 ranges")
    if not parser.recent_changes:
        raise SourceDataError("Recent changes section is empty")

    return {
        "canonical_url": parser.canonical_url,
        "title": parser.title,
        "published_date": _normalize_published_date(parser.published_date),
        "endpoint_rows": endpoint_rows,
        "firewall": {
            "hostname_patterns": firewall_patterns,
            "ip_ranges": [
                str(network)
                for network in sorted(
                    networks,
                    key=lambda item: (
                        item.version,
                        int(item.network_address),
                        item.prefixlen,
                    ),
                )
            ],
        },
        "recent_changes": parser.recent_changes,
    }


def _semantic_hash(data: dict[str, Any]) -> str:
    encoded = json.dumps(
        data, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_manifest(parsed: dict[str, Any]) -> dict[str, Any]:
    core = {
        "source": SOURCE_URL,
        "canonical_url": parsed["canonical_url"],
        "title": parsed["title"],
        "published_date": parsed["published_date"],
        "endpoint_rows": parsed["endpoint_rows"],
        "firewall": parsed["firewall"],
        "recent_changes": parsed["recent_changes"],
    }
    return {
        "schema_version": 1,
        **core,
        "semantic_sha256": _semantic_hash(core),
    }


def validate_manifest(manifest: Any) -> dict[str, Any]:
    expected_keys = {
        "schema_version",
        "source",
        "canonical_url",
        "title",
        "published_date",
        "endpoint_rows",
        "firewall",
        "recent_changes",
        "semantic_sha256",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_keys:
        raise SourceDataError("stored Apple manifest has an unsupported top-level schema")
    if manifest["schema_version"] != 1 or manifest["source"] != SOURCE_URL:
        raise SourceDataError("stored Apple manifest schema version or source is invalid")
    if manifest["canonical_url"] != SOURCE_URL:
        raise SourceDataError("stored Apple manifest canonical URL is invalid")
    if not isinstance(manifest["title"], str) or EXPECTED_TITLE not in manifest["title"]:
        raise SourceDataError("stored Apple manifest title is invalid")
    _normalize_published_date(manifest["published_date"])
    if not isinstance(manifest["endpoint_rows"], list) or len(manifest["endpoint_rows"]) < MIN_ROWS:
        raise SourceDataError("stored Apple manifest has too few endpoint rows")

    row_keys = {
        "table_index",
        "row_index",
        "section_id",
        "section",
        "subsection",
        "host",
        "ports",
        "protocols",
        "os",
        "description",
        "supports_proxies",
        "links",
    }
    unique_hosts: set[str] = set()
    for index, row in enumerate(manifest["endpoint_rows"], start=1):
        if not isinstance(row, dict) or set(row) != row_keys:
            raise SourceDataError(f"stored Apple row {index} schema mismatch")
        source_host, _ = classify_host(row["host"])
        if source_host != row["host"]:
            raise SourceDataError(f"stored Apple row {index} host is not canonical")
        unique_hosts.add(source_host)
        if (
            not isinstance(row["table_index"], int)
            or isinstance(row["table_index"], bool)
            or row["table_index"] < 1
            or not isinstance(row["row_index"], int)
            or isinstance(row["row_index"], bool)
            or row["row_index"] < 1
        ):
            raise SourceDataError(f"stored Apple row {index} has invalid source indexes")
        if (
            not isinstance(row["section_id"], str)
            or not isinstance(row["section"], str)
            or (row["subsection"] is not None and not isinstance(row["subsection"], str))
        ):
            raise SourceDataError(f"stored Apple row {index} has invalid section data")
        if (
            not isinstance(row["ports"], list)
            or not row["ports"]
            or any(not isinstance(port, int) or isinstance(port, bool) for port in row["ports"])
            or any(port < 1 or port > 65535 for port in row["ports"])
            or len(row["ports"]) != len(set(row["ports"]))
        ):
            raise SourceDataError(f"stored Apple row {index} has invalid ports")
        if (
            not isinstance(row["protocols"], list)
            or not row["protocols"]
            or any(protocol not in {"TCP", "UDP", "SSH"} for protocol in row["protocols"])
            or len(row["protocols"]) != len(set(row["protocols"]))
        ):
            raise SourceDataError(f"stored Apple row {index} has invalid protocols")
        for key in ("os", "description", "supports_proxies"):
            if not isinstance(row[key], str):
                raise SourceDataError(f"stored Apple row {index} has invalid {key}")
        if not isinstance(row["links"], list) or any(
            not isinstance(link, dict)
            or set(link) != {"field", "text", "href"}
            or link["field"] not in EXPECTED_HEADERS
            or not isinstance(link["text"], str)
            or not isinstance(link["href"], str)
            for link in row["links"]
        ):
            raise SourceDataError(f"stored Apple row {index} has invalid links")
    if len(unique_hosts) < MIN_UNIQUE_HOSTS:
        raise SourceDataError("stored Apple manifest has too few unique hosts")

    firewall = manifest["firewall"]
    if not isinstance(firewall, dict) or set(firewall) != {
        "hostname_patterns",
        "ip_ranges",
    }:
        raise SourceDataError("stored Apple firewall schema mismatch")
    patterns = firewall["hostname_patterns"]
    if not isinstance(patterns, list) or "*.apple.com" not in patterns:
        raise SourceDataError("stored Apple firewall hostname patterns are invalid")
    if patterns != sorted(set(patterns)):
        raise SourceDataError("stored Apple firewall hostname patterns are not canonical")
    for pattern in patterns:
        source_pattern, _ = classify_host(pattern)
        if source_pattern != pattern or not pattern.startswith("*."):
            raise SourceDataError(f"invalid stored firewall hostname pattern: {pattern!r}")
    ip_ranges = firewall["ip_ranges"]
    if not isinstance(ip_ranges, list) or not ip_ranges:
        raise SourceDataError("stored Apple firewall IP ranges are invalid")
    networks = []
    for value in ip_ranges:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise SourceDataError(f"invalid stored Apple CIDR: {value!r}") from exc
        if str(network) != value:
            raise SourceDataError(f"non-canonical stored Apple CIDR: {value!r}")
        networks.append(network)
    expected_networks = sorted(
        set(networks),
        key=lambda item: (item.version, int(item.network_address), item.prefixlen),
    )
    if networks != expected_networks:
        raise SourceDataError("stored Apple firewall IP ranges are not canonical")
    if not any(item.version == 4 for item in networks) or not any(
        item.version == 6 for item in networks
    ):
        raise SourceDataError("stored Apple firewall ranges must include IPv4 and IPv6")
    if not isinstance(manifest["recent_changes"], list) or not manifest["recent_changes"] or any(
        not isinstance(item, str) or not item for item in manifest["recent_changes"]
    ):
        raise SourceDataError("stored Apple recent changes are invalid")

    core = {key: manifest[key] for key in expected_keys - {"schema_version", "semantic_sha256"}}
    expected_hash = _semantic_hash(core)
    if manifest["semantic_sha256"] != expected_hash:
        raise SourceDataError("stored Apple semantic hash does not match its contents")
    return manifest


def render_outputs(manifest: dict[str, Any]) -> tuple[str, str]:
    manifest = validate_manifest(manifest)
    domains: set[str] = set()
    for row in manifest["endpoint_rows"]:
        _, domain = classify_host(row["host"])
        domains.add(domain)
    for pattern in manifest["firewall"]["hostname_patterns"]:
        _, domain = classify_host(pattern)
        domains.add(domain)

    published = manifest["published_date"]
    fingerprint = manifest["semantic_sha256"]
    domain_lines = [
        "# GENERATED DOMAIN-SET: Apple enterprise network hosts; do not edit manually.",
        f"# Source: {SOURCE_URL}",
        f"# Published date: {published}; semantic SHA-256: {fingerprint}",
        "# Exact source names stay exact; source *.example.com becomes .example.com.",
        *sorted(domains),
    ]

    ipv4: list[ipaddress.IPv4Network] = []
    ipv6: list[ipaddress.IPv6Network] = []
    for value in manifest["firewall"]["ip_ranges"]:
        network = ipaddress.ip_network(value, strict=True)
        (ipv4 if network.version == 4 else ipv6).append(network)
    rule_lines = [
        "# GENERATED RULE-SET: Apple-owned firewall IP ranges; do not edit manually.",
        f"# Source: {SOURCE_URL}",
        f"# Published date: {published}; semantic SHA-256: {fingerprint}",
        "# Policies belong in the consuming Surge profile.",
        *(f"IP-CIDR,{network},no-resolve" for network in ipv4),
        *(f"IP-CIDR6,{network},no-resolve" for network in ipv6),
    ]
    return "\n".join(domain_lines) + "\n", "\n".join(rule_lines) + "\n"


def serialize_manifest(manifest: dict[str, Any]) -> str:
    return json.dumps(
        validate_manifest(manifest), indent=2, ensure_ascii=False, sort_keys=True
    ) + "\n"


def _request_html(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "text/html,application/xhtml+xml",
            "User-Agent": "Tailored-Rulesets Apple enterprise endpoint updater",
        },
    )
    for attempt in range(len(RETRY_DELAYS) + 1):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                if response.status != 200:
                    raise SourceDataError(
                        f"unexpected HTTP status {response.status} for {url}"
                    )
                if response.geturl().rstrip("/") != SOURCE_URL:
                    raise SourceDataError(
                        f"unexpected final Apple URL: {response.geturl()!r}"
                    )
                content_type = response.headers.get_content_type()
                if content_type not in {"text/html", "application/xhtml+xml"}:
                    raise SourceDataError(
                        f"unexpected Apple content type: {content_type!r}"
                    )
                payload = response.read(MAX_RESPONSE_BYTES + 1)
                if len(payload) > MAX_RESPONSE_BYTES:
                    raise SourceDataError("Apple response exceeds 5 MiB")
                charset = response.headers.get_content_charset() or "utf-8"
                try:
                    return payload.decode(charset)
                except (LookupError, UnicodeDecodeError) as exc:
                    raise SourceDataError(
                        f"cannot decode Apple response as {charset!r}"
                    ) from exc
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise SourceDataError(
                    "Apple Support returned 429; wait for the next run"
                ) from exc
            retryable = 500 <= exc.code <= 599
            error: Exception = exc
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            retryable = True
            error = exc
        if not retryable or attempt == len(RETRY_DELAYS):
            raise SourceDataError(f"request failed for {url}: {error}") from error
        time.sleep(RETRY_DELAYS[attempt])
    raise AssertionError("unreachable")


def _atomic_replace_many(contents: dict[Path, str]) -> list[Path]:
    changed = [
        path
        for path, text in contents.items()
        if not path.exists() or path.read_text(encoding="utf-8") != text
    ]
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
    manifest = build_manifest(parse_article(_request_html(SOURCE_URL)))
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
        print("All Apple generated files are current.")
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
        raise SourceDataError(
            f"Apple generated outputs are stale: {', '.join(map(str, stale))}"
        )
    print(
        "PASS: Apple source and outputs match "
        f"({manifest['published_date']}, {manifest['semantic_sha256'][:12]})."
    )


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
