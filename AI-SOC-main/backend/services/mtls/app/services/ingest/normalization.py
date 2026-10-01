from datetime import datetime, timezone
import re
from typing import Dict, Any

ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_timestamp(value) -> datetime:
    """Parse common timestamp forms into a timezone-aware UTC datetime."""
    try:
        # numeric epoch
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=timezone.utc)

        s = str(value)
        # integer string epoch
        if s.isdigit():
            return datetime.fromtimestamp(int(s), tz=timezone.utc)

        # ISO strings ending with Z -> +00:00
        if s.endswith("Z"):
            s = s.replace("Z", "+00:00")

        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        # fallback to current time in UTC
        return datetime.now(timezone.utc)


def mask_ips(text: str) -> str:
    if not text:
        return text
    return ip_re.sub("[REDACTED_IP]", text)


def normalize_wazuh_alert(alert) -> Dict[str, Any]:
    """Return a dict suitable for constructing `BaseAlert` with normalized fields.

    Does not generate `id` — caller should set that. Keeps timestamp as
    a timezone-aware `datetime` (UTC) to satisfy the shared schema.
    """
    ts = parse_timestamp(alert.timestamp)

    rule = {
        "id": str(alert.rule_id) if alert.rule_id is not None else "",
        "description": alert.rule_description or "",
        "level": int(alert.rule_level) if alert.rule_level is not None else 0,
    }

    agent = {
        "id": alert.agent_id or "unknown",
        "name": alert.agent_name or "unknown",
        "ip": alert.agent_ip or "0.0.0.0",
    }

    normalized = {
        "timestamp": ts,
        "rule": rule,
        "agent": agent,
        "manager": None,
        "decoder": {"name": alert.decoder} if alert.decoder else None,
        "data": alert.data or {},
        "location": alert.location,
        "full_log": mask_ips(alert.full_log) if alert.full_log else None,
    }

    return normalized
