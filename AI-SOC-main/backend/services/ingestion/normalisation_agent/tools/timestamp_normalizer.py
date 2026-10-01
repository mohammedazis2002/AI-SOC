"""
Tool 3 — Timestamp Normaliser
==============================
Deterministic timestamp normalisation. No LLM.

Handles: ISO 8601, syslog (Nov 8 05:29:57), epoch seconds/milliseconds,
         any timezone → always returns UTC timezone-aware datetime.

This is the ONLY correct way to produce the ULF time field.
"""

import logging
import re
from datetime import datetime, timezone
from typing import Any, Optional, Union

logger = logging.getLogger(__name__)


def ocsf_time_ms(dt: datetime) -> int:
    """
    Convert a timezone-aware (or naive→UTC) datetime to OCSF `time`:
    Unix epoch milliseconds (UnifiedLogFormat.time).
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return int(dt.timestamp() * 1000)


def coerce_to_ocsf_time_ms(value: Any) -> int:
    """
    Coerce a ULF `time` value to OCSF milliseconds int.
    Accepts datetime, ISO string, epoch seconds, or epoch milliseconds.
    """
    if isinstance(value, datetime):
        return ocsf_time_ms(value)
    if isinstance(value, int):
        # Heuristic: epoch seconds are ~1e9–1e10; OCSF ms are ~1e12+
        if value < 1_000_000_000_000:
            return int(value * 1000)
        return value
    if isinstance(value, float):
        iv = int(value)
        if iv < 1_000_000_000_000:
            return int(value * 1000)
        return iv
    if isinstance(value, str) and value.strip():
        return ocsf_time_ms(normalize_timestamp(value))
    return ocsf_time_ms(datetime.now(timezone.utc))

# Syslog timestamp: "Nov  8 05:29:57" or "Nov 08 05:29:57"
_SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})$"
)
_MONTH_MAP = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4,
    "may": 5, "jun": 6, "jul": 7, "aug": 8,
    "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


def normalize_timestamp(raw: Union[str, int, float, None]) -> datetime:
    """
    Tool 3: Normalise any timestamp to a UTC timezone-aware datetime.

    Handles:
        - ISO 8601 with Z or +HH:MM offset
        - Syslog format: "Nov  8 05:29:57"
        - Unix epoch seconds (int/float with value < 2e10)
        - Unix epoch milliseconds (int/float with value >= 1e12)
        - None / empty → current UTC time

    Returns:
        datetime with tzinfo=UTC
    """
    if raw is None or raw == "":
        logger.debug("normalize_timestamp: no timestamp found — using now(UTC)")
        return datetime.now(timezone.utc)

    # Numeric epoch
    if isinstance(raw, (int, float)):
        return _from_epoch(raw)

    raw_str = str(raw).strip()

    if not raw_str:
        return datetime.now(timezone.utc)

    # Try ISO 8601 / RFC 3339 first (most common from modern SIEMs)
    iso_result = _try_iso(raw_str)
    if iso_result:
        return iso_result

    # Try syslog format
    syslog_result = _try_syslog(raw_str)
    if syslog_result:
        return syslog_result

    # Fallback: dateutil (handles ~90% of edge cases)
    util_result = _try_dateutil(raw_str)
    if util_result:
        return util_result

    logger.warning(f"normalize_timestamp: could not parse {raw_str!r} — using now(UTC)")
    return datetime.now(timezone.utc)


# ── Parsers ───────────────────────────────────────────────────────────────────

def _from_epoch(value: Union[int, float]) -> datetime:
    """Convert epoch int/float to UTC datetime."""
    if value >= 1e12:
        value = value / 1000.0   # milliseconds → seconds
    return datetime.fromtimestamp(value, tz=timezone.utc)


def _try_iso(s: str) -> Optional[datetime]:
    """Parse ISO 8601 / RFC 3339 strings."""
    # Replace Z with +00:00 for fromisoformat
    s_clean = s.replace("Z", "+00:00").replace("+0000", "+00:00")
    # Remove fractional seconds beyond 6 digits (Python max)
    s_clean = re.sub(r"(\.\d{6})\d+", r"\1", s_clean)
    try:
        dt = datetime.fromisoformat(s_clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def _try_syslog(s: str) -> Optional[datetime]:
    """Parse syslog format: 'Nov  8 05:29:57'"""
    m = _SYSLOG_PATTERN.match(s)
    if not m:
        return None
    month_str = m.group("month").lower()
    month = _MONTH_MAP.get(month_str)
    if not month:
        return None
    day = int(m.group("day"))
    h, mi, sec = map(int, m.group("time").split(":"))
    # Assume current year (syslog omits year)
    year = datetime.now(timezone.utc).year
    try:
        dt = datetime(year, month, day, h, mi, sec, tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _try_dateutil(s: str) -> Optional[datetime]:
    """Last-resort: dateutil.parser (handles ~90% of edge cases)."""
    try:
        from dateutil import parser as du_parser
        dt = du_parser.parse(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None
