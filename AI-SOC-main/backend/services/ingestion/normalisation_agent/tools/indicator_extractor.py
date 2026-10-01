"""
Tool 4 — Indicator Extractor
==============================
Deterministic extraction of all security indicators from a raw alert.
No LLM. Wraps and extends the existing extraction_helpers.py.

Extracts: src_ip, dst_ip, src_port, dst_port, protocol, hostname,
          username, process_name, pid, file_path, hashes (md5/sha256).
"""

import logging
import re
from typing import Any, Dict, List, Optional

from backend.services.ingestion.extraction_helpers import (
    extract_network_info,
    extract_username,
    extract_file_path,
    extract_process_info,
    extract_hostname,
)

logger = logging.getLogger(__name__)

_HASH_PATTERNS = {
    "md5":    re.compile(r"\b[0-9a-fA-F]{32}\b"),
    "sha256": re.compile(r"\b[0-9a-fA-F]{64}\b"),
    "sha1":   re.compile(r"\b[0-9a-fA-F]{40}\b"),
}

_PROTO_PATTERN = re.compile(
    r"\b(TCP|UDP|ICMP|HTTP|HTTPS|SSH|FTP|DNS|SMTP|RDP|SMB)\b",
    re.IGNORECASE,
)


def extract_indicators(raw_alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tool 4: Extract all security indicators from a raw alert.

    Tries structured fields first (deterministic), then falls back
    to regex over the full_log / raw text.

    Args:
        raw_alert: Unwrapped source dict (pass _source if ES export)

    Returns:
        {
            src_ip, dst_ip, src_port, dst_port, protocol,
            hostname, username, process_name, pid,
            file_path, hashes: {md5, sha256, sha1}
        }
        All values Optional — missing = None.
    """
    result: Dict[str, Any] = {
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "hostname": None,
        "username": None,
        "process_name": None,
        "pid": None,
        "file_path": None,
        "hashes": {},
    }

    # ── Structured field lookup (priority — exact, no regex noise) ────────────

    data = raw_alert.get("data") or {}
    agent = raw_alert.get("agent") or {}
    predecoder = raw_alert.get("predecoder") or {}

    # IPs and ports from structured data fields
    result["src_ip"] = _first(data, ["srcip", "src_ip", "srcIP", "src"])
    result["dst_ip"] = _first(data, ["dstip", "dst_ip", "dstIP", "dst"])
    result["src_port"] = _to_int(_first(data, ["srcport", "src_port", "sport"]))
    result["dst_port"] = _to_int(_first(data, ["dstport", "dst_port", "dport", "id.resp_p"]))
    result["protocol"] = _first(data, ["proto", "protocol", "transport"])
    result["username"] = _first(data, ["srcuser", "dstuser", "user", "username", "login"])
    result["file_path"] = _first(data, ["file", "filepath", "file_path", "path", "filename"])

    # Hostname from agent (Wazuh) or predecoder
    result["hostname"] = (
        agent.get("name")
        or predecoder.get("hostname")
        or _first(data, ["hostname", "host", "src_hostname"])
    )

    # Process info
    result["process_name"] = _first(data, ["process", "proc", "processname", "pname"])
    result["pid"] = _to_int(_first(data, ["pid", "process_id", "procid"]))

    # Hashes
    result["hashes"] = _extract_hashes(data)

    # ── Regex fallback on full_log / raw text ─────────────────────────────────
    full_log = raw_alert.get("full_log") or raw_alert.get("message") or ""

    if full_log and (not result["src_ip"] and not result["dst_ip"]):
        network = extract_network_info(full_log)
        result["src_ip"] = result["src_ip"] or network.source_ip
        result["dst_ip"] = result["dst_ip"] or network.destination_ip
        result["src_port"] = result["src_port"] or network.source_port
        result["dst_port"] = result["dst_port"] or network.destination_port
        result["protocol"] = result["protocol"] or network.protocol

    if full_log and not result["username"]:
        result["username"] = extract_username(full_log)

    if full_log and not result["hostname"]:
        result["hostname"] = extract_hostname(full_log)

    if full_log and not result["file_path"]:
        result["file_path"] = extract_file_path(full_log)

    if full_log and not result["process_name"]:
        proc_name, pid = extract_process_info(full_log)
        result["process_name"] = proc_name
        result["pid"] = result["pid"] or pid

    if full_log and not result["hashes"]:
        result["hashes"] = _extract_hashes_from_text(full_log)

    if full_log and not result["protocol"]:
        pm = _PROTO_PATTERN.search(full_log)
        if pm:
            result["protocol"] = pm.group(1).upper()

    # Normalise protocol to uppercase
    if result["protocol"]:
        result["protocol"] = result["protocol"].upper()

    logger.debug(
        f"extract_indicators: src={result['src_ip']}:{result['src_port']} "
        f"dst={result['dst_ip']}:{result['dst_port']} "
        f"user={result['username']!r} host={result['hostname']!r}"
    )
    return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def _first(d: Dict, keys: List[str]) -> Optional[str]:
    """Return the first non-empty value from a list of dict keys."""
    for k in keys:
        v = d.get(k)
        if v and str(v).strip():
            return str(v).strip()
    return None


def _to_int(val) -> Optional[int]:
    """Safe string/None → int conversion."""
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _extract_hashes(data: Dict) -> Dict[str, str]:
    hashes = {}
    for key in ["md5", "sha256", "sha1", "hash"]:
        val = data.get(key)
        if val and isinstance(val, str):
            hashes[key] = val.lower()
    return hashes


def _extract_hashes_from_text(text: str) -> Dict[str, str]:
    hashes = {}
    for hash_type, pattern in _HASH_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            hashes[hash_type] = matches[0].lower()
    return hashes
