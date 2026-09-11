#!/usr/bin/env python3
"""Build deterministic Surge rules from official Google endpoint sources."""

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
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = REPO_ROOT / "dist"
SOURCE_FILE = REPO_ROOT / "sources" / "google_endpoints.json"
DOMAINSET_FILE = DIST_DIR / "google_generated_domainset.txt"
RULESET_FILE = DIST_DIR / "google_generated_ruleset.txt"
GOOG_JSON_URL = "https://www.gstatic.com/ipranges/goog.json"
CLOUD_JSON_URL = "https://www.gstatic.com/ipranges/cloud.json"
RETRY_DELAYS = (5, 15, 45)
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
LABEL_RE = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)\Z")
IP_TOKEN_RE = re.compile(r"(?<![0-9A-Fa-f:.])(?:\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}|[0-9A-Fa-f:]+/\d{1,3})(?![0-9A-Fa-f:.])")
HOST_TOKEN_RE = re.compile(
    r"(?i)(?P<scheme>https?://)?"
    r"(?P<host>[a-z0-9*\[\]-]+(?:\.[a-z0-9*\[\]-]+)+)"
    r"(?::(?P<port>\d{1,5}))?(?P<tail>/[^\s<>,;)]*)?"
)

PAGE_SPECS = {
    "workspace": {"url": "https://knowledge.workspace.google.com/admin/getting-started/set-up-a-google-workspace-host-name-allowlist", "title": "Set up a Google Workspace host name allowlist", "framework": "devsite", "min_hosts": 35, "min_ips": 0},
    "firewall": {"url": "https://knowledge.workspace.google.com/admin/security/firewall-and-proxy-settings", "title": "Firewall and proxy settings", "framework": "devsite", "min_hosts": 55, "min_ips": 0},
    "ip_ranges": {"url": "https://knowledge.workspace.google.com/admin/security/obtain-google-ip-address-ranges", "title": "Obtain Google IP address ranges", "framework": "devsite", "min_hosts": 0, "min_ips": 0, "metadata_only": True},
    "chrome": {"url": "https://support.google.com/chrome/a/answer/6334001", "title": "Set up a hostname allowlist", "framework": "chrome", "min_hosts": 70, "min_ips": 0},
    "meet": {"url": "https://knowledge.workspace.google.com/admin/meet/prepare-your-network-for-meet-meetings-and-live-streams", "title": "Prepare your network for Meet meetings & live streams", "framework": "devsite", "min_hosts": 15, "min_ips": 6},
    "drive": {"url": "https://knowledge.workspace.google.com/admin/drive/drive-and-sites-firewall-and-proxy-settings", "title": "Drive and Sites firewall and proxy settings", "framework": "devsite", "min_hosts": 30, "min_ips": 0},
}
SKIP_HEADINGS = ("updates to", "previous updates", "related topics", "was this helpful", "need more help", "try these next steps")


class SourceDataError(ValueError):
    """An upstream response or stored manifest violates the contract."""


@dataclass
class Node:
    tag: str
    attrs: dict[str, str | None] = field(default_factory=dict)
    children: list[Node | str] = field(default_factory=list)

    def classes(self) -> set[str]:
        return set((self.attrs.get("class") or "").split())

    def text(self, skip_tags: set[str] | None = None) -> str:
        parts: list[str] = []
        skip_tags = skip_tags or set()
        def visit(value: Node | str) -> None:
            if isinstance(value, str):
                parts.append(value)
            elif value.tag not in skip_tags:
                for child in value.children:
                    visit(child)
        visit(self)
        return " ".join("".join(parts).split())

    def descendants(self, tag: str | None = None) -> Iterable[Node]:
        for child in self.children:
            if isinstance(child, Node):
                if tag is None or child.tag == tag:
                    yield child
                yield from child.descendants(tag)


class TreeParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = Node("document")
        self.stack = [self.root]
        self.saw_html_end = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        node = Node(tag.lower(), dict(attrs))
        self.stack[-1].children.append(node)
        if node.tag not in VOID_TAGS:
            self.stack.append(node)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.stack[-1].children.append(Node(tag.lower(), dict(attrs)))

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index].tag == tag:
                del self.stack[index:]
                if tag == "html":
                    self.saw_html_end = True
                return

    def handle_data(self, data: str) -> None:
        self.stack[-1].children.append(data)


def _validate_hostname(hostname: str) -> str:
    try:
        value = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise SourceDataError(f"invalid IDNA hostname: {hostname!r}") from exc
    if not value or len(value) > 253 or any(not LABEL_RE.fullmatch(x) for x in value.split(".")):
        raise SourceDataError(f"invalid hostname: {hostname!r}")
    return value


def classify_host(value: str) -> list[tuple[str, str]]:
    """Map one official hostname pattern to one or more Surge rules."""
    value = value.strip().lower().rstrip(".")
    value = value.replace("[0–9]", "[0-9]").replace("[0−9]", "[0-9]")
    value = value.replace("[your country identifier]", "[country]")
    if value in {"accounts.google.[country]", "accounts.google.co.[country]"}:
        return [("wildcard", "accounts.google.*")]
    if "[country]" in value:
        raise SourceDataError(f"unsupported country template: {value!r}")
    if "[0-9]" in value:
        if value.count("[0-9]") != 1:
            raise SourceDataError(f"unsupported numeric template: {value!r}")
        result: list[tuple[str, str]] = []
        for digit in "0123456789":
            result.extend(classify_host(value.replace("[0-9]", digit)))
        return result
    if "[" in value or "]" in value:
        raise SourceDataError(f"unknown hostname template: {value!r}")
    if "*" not in value:
        return [("domainset", _validate_hostname(value))]
    if value.startswith("*.") and value.count("*") == 1:
        return [("domainset", "." + _validate_hostname(value[2:]))]
    if "**" in value or any(not x for x in value.split(".")):
        raise SourceDataError(f"unsupported wildcard syntax: {value!r}")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise SourceDataError(f"wildcard hostname must be ASCII: {value!r}") from exc
    for label in value.split("."):
        if "*" not in label:
            _validate_hostname(label)
        elif label.replace("*", "") and not LABEL_RE.fullmatch(label.replace("*", "")):
            raise SourceDataError(f"invalid wildcard label: {value!r}")
    return [("wildcard", value)]


def _find_one(root: Node, predicate, description: str) -> Node:
    values = [node for node in root.descendants() if predicate(node)]
    if len(values) != 1:
        raise SourceDataError(f"expected one {description}, found {len(values)}")
    return values[0]


def _canonical_url(root: Node) -> str:
    values = [node.attrs.get("href") for node in root.descendants("link") if "canonical" in (node.attrs.get("rel") or "").split()]
    values = [value for value in values if value]
    if len(values) != 1:
        raise SourceDataError(f"expected one canonical URL, found {len(values)}")
    parsed = urllib.parse.urlsplit(values[0])
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _normalize_text(text: str) -> str:
    return text.replace("[0–9]", "[0-9]").replace("[0−9]", "[0-9]").replace("[your country identifier]", "[country]")


def _extract_host_tokens(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for match in HOST_TOKEN_RE.finditer(_normalize_text(text)):
        host = match.group("host").lower().rstrip(".")
        if host.rsplit(".", 1)[-1].isdigit():
            continue
        classify_host(host)
        port = int(match.group("port")) if match.group("port") else None
        if port is not None and not 1 <= port <= 65535:
            raise SourceDataError(f"port outside 1-65535: {match.group(0)!r}")
        tail = (match.group("tail") or "").rstrip(".,")
        protocol = tail[1:].upper() if tail.upper() in {"/HTTP", "/HTTPS"} and not match.group("scheme") else None
        path = None if not tail or protocol else tail
        records.append({"source": match.group(0).rstrip(".,"), "host": host, "path": path, "port": port, "protocol": protocol})
    return records


def _extract_ip_tokens(text: str) -> list[str]:
    values: list[str] = []
    for token in IP_TOKEN_RE.findall(text):
        try:
            values.append(str(ipaddress.ip_network(token, strict=True)))
        except ValueError as exc:
            raise SourceDataError(f"invalid or non-canonical CIDR: {token!r}") from exc
    return values


def _has_descendant_block(node: Node) -> bool:
    return any(x.tag in {"p", "li", "td", "code"} for x in node.descendants())


def parse_page_html(page_id: str, html: str) -> dict[str, Any]:
    if page_id not in PAGE_SPECS:
        raise SourceDataError(f"unknown page id: {page_id}")
    spec = PAGE_SPECS[page_id]
    parser = TreeParser()
    parser.feed(html)
    parser.close()
    if not parser.saw_html_end:
        raise SourceDataError(f"{page_id}: HTML appears truncated")
    canonical = _canonical_url(parser.root)
    if canonical != spec["url"].rstrip("/"):
        raise SourceDataError(f"{page_id}: unexpected canonical URL {canonical!r}")
    h1s = [x for x in parser.root.descendants("h1") if spec["title"] in x.text()]
    if len(h1s) != 1:
        raise SourceDataError(f"{page_id}: expected one matching h1, found {len(h1s)}")
    if spec["framework"] == "devsite":
        body = _find_one(parser.root, lambda n: n.tag == "div" and "devsite-article-body" in n.classes(), f"{page_id} article body")
    else:
        body = _find_one(parser.root, lambda n: n.tag == "div" and "article-content-container" in n.classes(), f"{page_id} article body")
    updated = None
    match = re.search(r"Last updated\s+(\d{4}-\d{2}-\d{2})\s+UTC", parser.root.text())
    if match:
        updated = match.group(1)
    elif page_id == "chrome":
        match = re.search(r"([A-Z][a-z]{2}\s+\d{1,2},\s+\d{4}):\s+Added", body.text())
        updated = match.group(1) if match else None
    if page_id == "ip_ranges":
        hrefs = {x.attrs.get("href") for x in body.descendants("a")}
        if GOOG_JSON_URL not in hrefs or CLOUD_JSON_URL not in hrefs:
            raise SourceDataError("ip_ranges: official JSON links are missing")
        return {"id": page_id, "url": spec["url"], "canonical_url": canonical, "title": spec["title"], "last_updated": updated, "records": []}

    records: list[dict[str, Any]] = []
    headings: dict[int, str] = {}
    active = page_id not in {"chrome", "meet"}
    def walk(node: Node) -> None:
        nonlocal active
        if node.tag in {"h2", "h3", "h4"}:
            level = int(node.tag[1])
            heading = node.text({"sup"})
            for old in list(headings):
                if old >= level:
                    del headings[old]
            headings[level] = heading
            lowered = heading.casefold()
            if page_id == "chrome" and lowered.startswith("hostname allowlist for all chromeos"):
                active = True
            if page_id == "meet" and level == 4:
                if lowered.startswith(("step 2:", "step 3:")):
                    active = True
                elif lowered.startswith("step "):
                    active = False
            if any(lowered.startswith(prefix) for prefix in SKIP_HEADINGS):
                active = False
            return
        is_block = node.tag in {"p", "li", "td", "code"} or (node.tag == "div" and not _has_descendant_block(node))
        if active and is_block:
            text = node.text({"sup"})
            if page_id == "chrome" and re.match(r"^\d+\s", text):
                text = ""
            if page_id == "chrome" and text.startswith("For more information, see What is"):
                text = ""
            section = [headings[level] for level in sorted(headings)]
            optional = any("optional" in value.casefold() for value in section)
            for host in _extract_host_tokens(text):
                records.append({"type": "host", "section": section, "optional": optional, "raw": text, **host})
            for cidr in _extract_ip_tokens(text):
                records.append({"type": "ip", "section": section, "optional": optional, "raw": text, "cidr": cidr})
        for child in node.children:
            if isinstance(child, Node):
                walk(child)
    walk(body)
    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for record in records:
        if record["type"] == "host":
            key = ("host", record["host"], record["path"], record["port"], record["protocol"], tuple(record["section"]), record["optional"])
        else:
            key = ("ip", record["cidr"], tuple(record["section"]), record["optional"])
        unique.setdefault(key, record)
    records = sorted(unique.values(), key=lambda r: (r["type"], r.get("host", r.get("cidr", "")), tuple(r["section"]), r.get("path") or "", r.get("port") or 0))
    host_count = sum(x["type"] == "host" for x in records)
    ip_count = sum(x["type"] == "ip" for x in records)
    if host_count < spec["min_hosts"] or ip_count < spec["min_ips"]:
        raise SourceDataError(f"{page_id}: parsed too few records (hosts={host_count}, ips={ip_count})")
    return {"id": page_id, "url": spec["url"], "canonical_url": canonical, "title": spec["title"], "last_updated": updated, "records": records}


def normalize_prefix_payload(name: str, payload: Any) -> dict[str, Any]:
    expected = {"syncToken", "creationTime", "prefixes"}
    if not isinstance(payload, dict) or set(payload) != expected:
        raise SourceDataError(f"{name}: unexpected JSON schema")
    token, creation, prefixes = payload["syncToken"], payload["creationTime"], payload["prefixes"]
    if not isinstance(token, str) or not token.isdigit():
        raise SourceDataError(f"{name}: invalid syncToken")
    if not isinstance(creation, str) or not creation:
        raise SourceDataError(f"{name}: invalid creationTime")
    if not isinstance(prefixes, list) or not prefixes:
        raise SourceDataError(f"{name}: empty prefixes")
    allowed = {"ipv4Prefix", "ipv6Prefix"} if name == "goog" else {"ipv4Prefix", "ipv6Prefix", "service", "scope"}
    normalized: list[dict[str, str]] = []
    for item in prefixes:
        if not isinstance(item, dict) or not set(item) <= allowed:
            raise SourceDataError(f"{name}: invalid prefix record")
        address_keys = set(item) & {"ipv4Prefix", "ipv6Prefix"}
        if len(address_keys) != 1:
            raise SourceDataError(f"{name}: prefix record must have one address family")
        key = next(iter(address_keys))
        try:
            network = ipaddress.ip_network(item[key], strict=True)
        except (TypeError, ValueError) as exc:
            raise SourceDataError(f"{name}: invalid or non-canonical prefix {item.get(key)!r}") from exc
        if (key == "ipv4Prefix") != (network.version == 4):
            raise SourceDataError(f"{name}: prefix family mismatch")
        record = dict(item)
        record[key] = str(network)
        if name == "cloud" and (not isinstance(record.get("service"), str) or not isinstance(record.get("scope"), str)):
            raise SourceDataError("cloud: service and scope are required")
        normalized.append(record)
    normalized.sort(key=lambda x: (ipaddress.ip_network(x.get("ipv4Prefix") or x["ipv6Prefix"]).version, int(ipaddress.ip_network(x.get("ipv4Prefix") or x["ipv6Prefix"]).network_address), ipaddress.ip_network(x.get("ipv4Prefix") or x["ipv6Prefix"]).prefixlen, x.get("service", ""), x.get("scope", "")))
    return {"url": GOOG_JSON_URL if name == "goog" else CLOUD_JSON_URL, "sync_token": token, "creation_time": creation, "prefixes": normalized}


def derive_default_ranges(goog: dict[str, Any], cloud: dict[str, Any]) -> list[str]:
    if goog["sync_token"] != cloud["sync_token"]:
        raise SourceDataError("goog.json and cloud.json syncToken mismatch")
    google_networks = [ipaddress.ip_network(x.get("ipv4Prefix") or x["ipv6Prefix"]) for x in goog["prefixes"]]
    cloud_networks = [ipaddress.ip_network(x.get("ipv4Prefix") or x["ipv6Prefix"]) for x in cloud["prefixes"]]
    result = []
    for source_network in google_networks:
        current = [source_network]
        for excluded in (network for network in cloud_networks if network.version == source_network.version):
            next_ranges = []
            for network in current:
                if not network.overlaps(excluded):
                    next_ranges.append(network)
                elif excluded == network or excluded.supernet_of(network):
                    continue
                elif network.supernet_of(excluded):
                    next_ranges.extend(network.address_exclude(excluded))
                else:
                    raise SourceDataError(f"unexpected partial CIDR overlap: {network}, {excluded}")
            current = next_ranges
        result.extend(current)
    if not any(x.version == 4 for x in result) or not any(x.version == 6 for x in result):
        raise SourceDataError("derived Google default ranges must contain IPv4 and IPv6")
    unique = {str(network): network for network in result}
    return [str(x) for x in sorted(unique.values(), key=lambda x: (x.version, int(x.network_address), x.prefixlen))]


def _semantic_core(manifest: dict[str, Any]) -> dict[str, Any]:
    pages = []
    for page in manifest["pages"]:
        pages.append({key: value for key, value in page.items() if key != "last_updated"})
    return {
        "pages": pages,
        "ip_sources": {
            name: {"url": block["url"], "prefixes": block["prefixes"]}
            for name, block in manifest["ip_sources"].items()
        },
        "default_ranges": manifest["default_ranges"],
    }


def _semantic_hash(manifest: dict[str, Any]) -> str:
    payload = json.dumps(_semantic_core(manifest), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_manifest(html_pages: dict[str, str], goog_payload: Any, cloud_payload: Any) -> dict[str, Any]:
    if set(html_pages) != set(PAGE_SPECS):
        raise SourceDataError("HTML inputs must contain exactly the configured Google pages")
    pages = [parse_page_html(page_id, html_pages[page_id]) for page_id in PAGE_SPECS]
    goog = normalize_prefix_payload("goog", goog_payload)
    cloud = normalize_prefix_payload("cloud", cloud_payload)
    manifest = {
        "schema_version": 1,
        "pages": pages,
        "ip_sources": {"goog": goog, "cloud": cloud},
        "default_ranges": derive_default_ranges(goog, cloud),
        "semantic_sha256": "",
    }
    manifest["semantic_sha256"] = _semantic_hash(manifest)
    return validate_manifest(manifest)


def _validate_stored_record(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict) or record.get("type") not in {"host", "ip"}:
        raise SourceDataError("stored page record has an invalid type")
    common = {"type", "section", "optional", "raw"}
    expected = common | ({"source", "host", "path", "port", "protocol"} if record["type"] == "host" else {"cidr"})
    if set(record) != expected or not isinstance(record["section"], list) or not isinstance(record["optional"], bool) or not isinstance(record["raw"], str):
        raise SourceDataError("stored page record schema mismatch")
    if any(not isinstance(x, str) for x in record["section"]):
        raise SourceDataError("stored page record has invalid section")
    if record["type"] == "host":
        if not all(isinstance(record[key], str) for key in ("source", "host")):
            raise SourceDataError("stored host record has invalid strings")
        if record["path"] is not None and not isinstance(record["path"], str):
            raise SourceDataError("stored host record has invalid path")
        if record["port"] is not None and (not isinstance(record["port"], int) or not 1 <= record["port"] <= 65535):
            raise SourceDataError("stored host record has invalid port")
        if record["protocol"] not in {None, "HTTP", "HTTPS"}:
            raise SourceDataError("stored host record has invalid protocol")
        classify_host(record["host"])
    else:
        try:
            if str(ipaddress.ip_network(record["cidr"], strict=True)) != record["cidr"]:
                raise ValueError
        except (TypeError, ValueError) as exc:
            raise SourceDataError("stored IP record has invalid CIDR") from exc
    return record


def validate_manifest(manifest: Any) -> dict[str, Any]:
    expected = {"schema_version", "pages", "ip_sources", "default_ranges", "semantic_sha256"}
    if not isinstance(manifest, dict) or set(manifest) != expected or manifest["schema_version"] != 1:
        raise SourceDataError("stored Google manifest has an unsupported top-level schema")
    pages = manifest["pages"]
    if not isinstance(pages, list) or [page.get("id") for page in pages if isinstance(page, dict)] != list(PAGE_SPECS):
        raise SourceDataError("stored Google manifest has unexpected pages")
    for page in pages:
        if set(page) != {"id", "url", "canonical_url", "title", "last_updated", "records"}:
            raise SourceDataError(f"stored {page.get('id')} page schema mismatch")
        spec = PAGE_SPECS[page["id"]]
        if page["url"] != spec["url"] or page["canonical_url"] != spec["url"].rstrip("/") or page["title"] != spec["title"]:
            raise SourceDataError(f"stored {page['id']} metadata mismatch")
        if page["last_updated"] is not None and not isinstance(page["last_updated"], str):
            raise SourceDataError(f"stored {page['id']} update metadata is invalid")
        if not isinstance(page["records"], list):
            raise SourceDataError(f"stored {page['id']} records are invalid")
        for record in page["records"]:
            _validate_stored_record(record)
        host_count = sum(x["type"] == "host" for x in page["records"])
        ip_count = sum(x["type"] == "ip" for x in page["records"])
        if host_count < spec["min_hosts"] or ip_count < spec["min_ips"]:
            raise SourceDataError(f"stored {page['id']} contains too few records")
    blocks = manifest["ip_sources"]
    if not isinstance(blocks, dict) or set(blocks) != {"goog", "cloud"}:
        raise SourceDataError("stored Google IP source schema mismatch")
    normalized_blocks: dict[str, dict[str, Any]] = {}
    for name in ("goog", "cloud"):
        block = blocks[name]
        if not isinstance(block, dict) or set(block) != {"url", "sync_token", "creation_time", "prefixes"}:
            raise SourceDataError(f"stored {name} source schema mismatch")
        camel = {"syncToken": block["sync_token"], "creationTime": block["creation_time"], "prefixes": block["prefixes"]}
        normalized = normalize_prefix_payload(name, camel)
        if normalized != block:
            raise SourceDataError(f"stored {name} source is not canonical")
        normalized_blocks[name] = normalized
    expected_ranges = derive_default_ranges(normalized_blocks["goog"], normalized_blocks["cloud"])
    if manifest["default_ranges"] != expected_ranges:
        raise SourceDataError("stored default Google ranges are stale")
    if manifest["semantic_sha256"] != _semantic_hash(manifest):
        raise SourceDataError("stored Google semantic hash mismatch")
    return manifest


def render_outputs(manifest: dict[str, Any]) -> tuple[str, str]:
    manifest = validate_manifest(manifest)
    domains: set[str] = set()
    wildcards: set[str] = set()
    ipv4: set[ipaddress.IPv4Network] = set()
    ipv6: set[ipaddress.IPv6Network] = set()
    for page in manifest["pages"]:
        for record in page["records"]:
            if record["type"] == "host":
                for kind, value in classify_host(record["host"]):
                    (domains if kind == "domainset" else wildcards).add(value)
            else:
                network = ipaddress.ip_network(record["cidr"], strict=True)
                (ipv4 if network.version == 4 else ipv6).add(network)
    for value in manifest["default_ranges"]:
        network = ipaddress.ip_network(value, strict=True)
        (ipv4 if network.version == 4 else ipv6).add(network)
    fingerprint = manifest["semantic_sha256"]
    domain_lines = [
        "# GENERATED DOMAIN-SET: official Google Workspace, ChromeOS and service endpoints; do not edit manually.",
        f"# Semantic SHA-256: {fingerprint}",
        "# Exact source names stay exact; source *.example.com becomes .example.com.",
        *sorted(domains),
    ]
    rule_lines = [
        "# GENERATED RULE-SET: official Google complex host patterns and IP ranges; do not edit manually.",
        f"# IP syncToken: {manifest['ip_sources']['goog']['sync_token']}; semantic SHA-256: {fingerprint}",
        "# accounts.google.[country] is represented as accounts.google.* by explicit repository policy.",
        "# Policies belong in the consuming Surge profile.",
        *(f"DOMAIN-WILDCARD,{value}" for value in sorted(wildcards)),
        *(f"IP-CIDR,{network},no-resolve" for network in sorted(ipv4, key=lambda x: (int(x.network_address), x.prefixlen))),
        *(f"IP-CIDR6,{network},no-resolve" for network in sorted(ipv6, key=lambda x: (int(x.network_address), x.prefixlen))),
    ]
    return "\n".join(domain_lines) + "\n", "\n".join(rule_lines) + "\n"


def serialize_manifest(manifest: dict[str, Any]) -> str:
    return json.dumps(validate_manifest(manifest), indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def _request(url: str, accept: str) -> tuple[bytes, str, str | None]:
    request = urllib.request.Request(url, headers={"Accept": accept, "Accept-Language": "en-US,en;q=0.9", "User-Agent": "Tailored-Rulesets Google endpoint updater"})
    for attempt in range(len(RETRY_DELAYS) + 1):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                if response.status != 200:
                    raise SourceDataError(f"unexpected HTTP status {response.status} for {url}")
                payload = response.read(MAX_RESPONSE_BYTES + 1)
                if len(payload) > MAX_RESPONSE_BYTES:
                    raise SourceDataError(f"response exceeds 5 MiB: {url}")
                return payload, response.geturl().rstrip("/"), response.headers.get_content_charset()
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise SourceDataError(f"Google source returned 429: {url}") from exc
            retryable = 500 <= exc.code <= 599
            error: Exception = exc
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            retryable = True
            error = exc
        if not retryable or attempt == len(RETRY_DELAYS):
            raise SourceDataError(f"request failed for {url}: {error}") from error
        time.sleep(RETRY_DELAYS[attempt])
    raise AssertionError("unreachable")


def _request_html(page_id: str) -> str:
    url = PAGE_SPECS[page_id]["url"]
    payload, final_url, charset = _request(url, "text/html,application/xhtml+xml")
    if final_url != url.rstrip("/"):
        raise SourceDataError(f"{page_id}: unexpected final URL {final_url!r}")
    try:
        return payload.decode(charset or "utf-8")
    except (LookupError, UnicodeDecodeError) as exc:
        raise SourceDataError(f"{page_id}: cannot decode HTML") from exc


def _request_json(url: str) -> Any:
    payload, final_url, _ = _request(url, "application/json")
    if final_url != url.rstrip("/"):
        raise SourceDataError(f"unexpected final JSON URL {final_url!r}")
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceDataError(f"invalid JSON response from {url}") from exc


def _fetch_ip_pair() -> tuple[Any, Any]:
    for attempt in range(len(RETRY_DELAYS) + 1):
        goog_payload, cloud_payload = _request_json(GOOG_JSON_URL), _request_json(CLOUD_JSON_URL)
        goog = normalize_prefix_payload("goog", goog_payload)
        cloud = normalize_prefix_payload("cloud", cloud_payload)
        if goog["sync_token"] == cloud["sync_token"]:
            return goog_payload, cloud_payload
        if attempt == len(RETRY_DELAYS):
            raise SourceDataError("goog.json and cloud.json syncToken mismatch after retries")
        time.sleep(RETRY_DELAYS[attempt])
    raise AssertionError("unreachable")


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


def _read_manifest_if_valid() -> dict[str, Any] | None:
    if not SOURCE_FILE.exists():
        return None
    try:
        return validate_manifest(json.loads(SOURCE_FILE.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, SourceDataError) as exc:
        print(f"Stored Google manifest will be refreshed: {exc}", file=sys.stderr)
        return None


def update() -> list[Path]:
    html_pages = {page_id: _request_html(page_id) for page_id in PAGE_SPECS}
    goog_payload, cloud_payload = _fetch_ip_pair()
    candidate = build_manifest(html_pages, goog_payload, cloud_payload)
    stored = _read_manifest_if_valid()
    manifest = stored if stored and stored["semantic_sha256"] == candidate["semantic_sha256"] else candidate
    domainset, ruleset = render_outputs(manifest)
    changed = _atomic_replace_many({SOURCE_FILE: serialize_manifest(manifest), DOMAINSET_FILE: domainset, RULESET_FILE: ruleset})
    if changed:
        print("Updated: " + ", ".join(str(path.relative_to(REPO_ROOT)) for path in changed))
    else:
        print("All Google generated files are current.")
    return changed


def check() -> None:
    if not SOURCE_FILE.exists():
        raise SourceDataError(f"missing source manifest: {SOURCE_FILE}")
    manifest = validate_manifest(json.loads(SOURCE_FILE.read_text(encoding="utf-8")))
    domainset, ruleset = render_outputs(manifest)
    expected = {DOMAINSET_FILE: domainset, RULESET_FILE: ruleset}
    stale = [path.relative_to(REPO_ROOT) for path, text in expected.items() if not path.exists() or path.read_text(encoding="utf-8") != text]
    if stale:
        raise SourceDataError(f"Google generated outputs are stale: {', '.join(map(str, stale))}")
    print(f"PASS: Google source and outputs match ({manifest['ip_sources']['goog']['sync_token']}, {manifest['semantic_sha256'][:12]}).")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate committed source and outputs without network access or writes")
    args = parser.parse_args()
    try:
        check() if args.check else update()
    except (OSError, SourceDataError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
