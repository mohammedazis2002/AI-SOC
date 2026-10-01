"""
Drift Detector
==============
Detects schema drift: when a previously-populated ULF field returns None
on N consecutive alerts for the same schema fingerprint.

This signals that the source schema has changed (field renamed/moved) without
the top-level key structure changing (so the fingerprint didn't update).

On detecting drift:
  - Logs the affected field and fingerprint
  - Calls cache.invalidate() to trigger a full LLM re-learn on the next alert
"""

import logging
from collections import defaultdict, deque
from typing import Any, Dict, Set

logger = logging.getLogger(__name__)

DRIFT_WINDOW = 10       # consecutive Nones before declaring drift
TRACKED_FIELDS = {      # ULF fields worth tracking for drift
    "time", "severity_id", "finding",
    "src_endpoint", "dst_endpoint", "actor",
}


class DriftDetector:
    """
    Tracks per-fingerprint field presence history.
    Uses a sliding window of the last DRIFT_WINDOW alerts per field.
    """

    def __init__(self):
        # {fingerprint: {field_name: deque([True/False, ...])}}
        self._history: Dict[str, Dict[str, deque]] = defaultdict(
            lambda: defaultdict(lambda: deque(maxlen=DRIFT_WINDOW))
        )
        self._drifted: Set[str] = set()     # fingerprints with active drift

    def record(self, fingerprint: str, ulf: Dict[str, Any]) -> Set[str]:
        """
        Record field presence for a successfully applied template.

        Args:
            fingerprint: Schema fingerprint
            ulf:         The ULF dict produced from the template

        Returns:
            Set of field names that are drifting (all None in last DRIFT_WINDOW alerts)
        """
        if fingerprint in self._drifted:
            return set()    # Already flagged — cache.invalidate was called

        drifting_now = set()
        history = self._history[fingerprint]

        for field in TRACKED_FIELDS:
            present = ulf.get(field) is not None
            history[field].append(present)

            # Declare drift when the full window is all False
            if (
                len(history[field]) == DRIFT_WINDOW
                and not any(history[field])
            ):
                logger.warning(
                    f"Schema drift detected for fingerprint [{fingerprint[:8]}]: "
                    f"field '{field}' has been None for {DRIFT_WINDOW} consecutive alerts. "
                    f"Triggering template re-learn."
                )
                drifting_now.add(field)

        if drifting_now:
            self._drifted.add(fingerprint)

        return drifting_now

    def clear_drift(self, fingerprint: str) -> None:
        """Clear drift status after template has been refreshed."""
        self._drifted.discard(fingerprint)
        self._history.pop(fingerprint, None)
        logger.info(f"Drift cleared for [{fingerprint[:8]}] — template refreshed")
