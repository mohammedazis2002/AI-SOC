"""
SOAR Alert ID Generator
========================
Generates deterministic, traceable alert IDs tagged by the AI-SOC system.

Format: SOAR-YYYYMMDD-XXXXXXXX
  - YYYYMMDD: date derived from alert timestamp (UTC)
  - XXXXXXXX: 8-char lowercase hex from MD5(source_id + date_str)

Deterministic from source_id + date → safe to retry; no duplicates on reprocessing.
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


def generate_alert_id(
    source_id: str,
    alert_time: Optional[datetime] = None,
) -> str:
    """
    Generate a deterministic SOAR alert ID.

    Args:
        source_id:   Original SIEM alert ID (Elasticsearch _id, Wazuh id, etc.).
                     Used as entropy input — retrying with the same source alert
                     always produces the same SOAR ID.
        alert_time:  UTC datetime of the alert. If None, uses current UTC time.

    Returns:
        str: e.g. "SOAR-20251107-3f8a2c1d"
    """
    if alert_time is None:
        alert_time = datetime.now(timezone.utc)
    elif alert_time.tzinfo is None:
        # Localise naive datetimes to UTC
        alert_time = alert_time.replace(tzinfo=timezone.utc)

    date_str = alert_time.strftime("%Y%m%d")

    # 8 deterministic hex chars from hash of source_id + date
    hash_input = f"{source_id}:{date_str}"
    hex_suffix = hashlib.md5(hash_input.encode()).hexdigest()[:8]

    alert_id = f"SOAR-{date_str}-{hex_suffix}"
    logger.debug(f"Generated alert_id={alert_id} from source_id={source_id!r}")
    return alert_id
