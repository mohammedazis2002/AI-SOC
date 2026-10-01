"""
Tool 2 — Event Classifier
==========================
Determines which OCSF event class + activity this alert belongs to.

LLM-driven for new/unknown schemas. Cached immediately after first successful
classification for a given schema fingerprint.

No hardcoded if/else routing logic. The LLM reasons from examples and
a structured decision prompt. For OCSF class collisions (e.g. auth failure
+ network traffic), the LLM picks the primary security action class.
"""

import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ── OCSF Event Classes in scope ────────────────────────────────────────────────
# Focused on security-relevant classes only.
OCSF_CLASSES = {
    3002: {"name": "Authentication",        "category_uid": 3, "category_name": "Identity & Access Management"},
    4001: {"name": "Network Activity",      "category_uid": 4, "category_name": "Network Activity"},
    4002: {"name": "HTTP Activity",         "category_uid": 4, "category_name": "Network Activity"},
    4003: {"name": "DNS Activity",          "category_uid": 4, "category_name": "Network Activity"},
    1001: {"name": "File System Activity",  "category_uid": 1, "category_name": "System Activity"},
    1002: {"name": "Kernel Activity",       "category_uid": 1, "category_name": "System Activity"},
    1003: {"name": "Process Activity",      "category_uid": 1, "category_name": "System Activity"},
    2001: {"name": "Vulnerability Finding", "category_uid": 2, "category_name": "Findings"},
    2002: {"name": "Compliance Finding",    "category_uid": 2, "category_name": "Findings"},
    2004: {"name": "Detection Finding",     "category_uid": 2, "category_name": "Findings"},
}

# Activity IDs per class (most common)
ACTIVITY_IDS = {
    3002: {1: "Unknown", 2: "Logon", 3: "Logoff", 4: "Authentication Ticket", 99: "Other"},
    4001: {1: "Unknown", 2: "Open", 3: "Close", 4: "Reset", 5: "Fail", 6: "Traffic", 7: "Connect", 8: "Disconnect"},
    4002: {1: "Unknown", 2: "Connect", 3: "Receive", 4: "Refuse", 5: "Close", 6: "Clear"},
    4003: {1: "Unknown", 2: "Query", 3: "Response", 4: "Traffic"},
    1001: {1: "Unknown", 2: "Create", 3: "Read", 4: "Update", 5: "Delete", 6: "Rename"},
    1002: {1: "Unknown", 2: "Set", 3: "Read"},
    1003: {1: "Unknown", 2: "Launch", 3: "Terminate", 4: "Inject", 5: "Open"},
    2001: {1: "Unknown", 2: "Create", 3: "Update", 4: "Close"},
    2002: {1: "Unknown", 2: "Create", 3: "Update", 4: "Close"},
    2004: {1: "Detected", 2: "Updated", 3: "Closed", 4: "Reopened"},
}

_CLASSIFICATION_PROMPT = """You are classifying a security alert into a single OCSF (Open Cybersecurity Schema Framework) event class.

## OCSF Event Classes Available
| class_uid | class_name           | Use when...                                                          |
|-----------|----------------------|----------------------------------------------------------------------|
| 3002      | Authentication       | Primary action is login/logoff/auth failure/account access/brute-force |
| 4001      | Network Activity     | Primary action is network connection, firewall block/allow/deny     |
| 4002      | HTTP Activity        | Primary action is HTTP/HTTPS request, web proxy, URL filter         |
| 4003      | DNS Activity         | Primary action is DNS lookup/query/response/block                   |
| 1001      | File System Activity | Primary action is file read/write/delete/modify/create              |
| 1003      | Process Activity     | Primary action is process launch/terminate/inject                   |
| 2001      | Vulnerability Finding| Alert reports a known CVE, vulnerability scan result                |
| 2004      | Detection Finding    | Generic security detection (default — use only if nothing fits)     |

## Decision Rule
Pick the class matching the PRIMARY SECURITY ACTION performed by the actor.
If multiple classes could apply, the ACTION takes priority over the VECTOR/MEDIUM.

## Collision Examples
| Scenario                                          | Pick     | Reason                                          |
|---------------------------------------------------|----------|-------------------------------------------------|
| SSH brute force from 1.2.3.4 (auth fail + network) | 3002     | auth failure IS the event, network = vector    |
| Firewall blocked 1.2.3.4:443 BLOCKALL             | 4001     | network block IS the event                      |
| /etc/passwd modified by process X                 | 1001     | file modification IS the event                  |
| DNS query for c2.evil.com blocked                 | 4003     | DNS IS the event                                |
| Login success + lateral movement                  | 3002     | authentication IS the specific action            |
| HTTP request from malicious IP                    | 4002     | HTTP request IS the event                       |
| Wazuh SCA policy failure (compliance)             | 2002     | compliance check IS the event                   |
| Generic IDS/anomaly alert with no specific class  | 2004     | fallback Detection Finding                       |

## Schema Info
{schema_summary}

## Sample Fields from Alert
{sample_fields}

## Response (JSON only, no explanation)
{{
  "class_uid": <int>,
  "activity_id": <int>,
  "reasoning": "<one sentence>"
}}"""


DEFAULT_CLASSIFICATION = {
    "class_uid": 2004,
    "class_name": "Detection Finding",
    "category_uid": 2,
    "category_name": "Findings",
    "activity_id": 1,
    "activity_name": "Detected",
}

# ── Heuristic fast-path (no LLM) ─────────────────────────────────────────────
# Applied BEFORE calling the LLM. Covers the vast majority of Wazuh/known alerts.
_HEURISTIC_RULES = [
    # (decoder keyword, l1 signal, data signal) → (class_uid, activity_id)
    (lambda d, l1, data: "auth" in d or "ssh" in d or "pam" in d,        3002, 2),
    (lambda d, l1, data: "firewall" in d or "paloalto" in d or "nftables" in d, 4001, 6),
    (lambda d, l1, data: "web" in d or "nginx" in d or "apache" in d or "iis" in d, 4002, 3),
    (lambda d, l1, data: "dns" in d,                                       4003, 2),
    (lambda d, l1, data: "syscheck" in d or "fim" in d or "file" in d,   1001, 4),
    (lambda d, l1, data: "process" in d or "audit" in d,                  1003, 2),
    (lambda d, l1, data: "vulnerability" in d or "cve" in data,           2001, 2),
    (lambda d, l1, data: "zscaler" in d or "proxy" in d,                  4002, 3),
]


class EventClassifier:
    """
    Tool 2: Classifies an alert into an OCSF event class.

    Fast path: heuristic rules (decoder name → class, no LLM).
    LLM path: Called when heuristics don't match. Result cached by fingerprint.
    """

    def __init__(self, llm_client=None):
        self._llm = llm_client
        # In-process cache: {fingerprint → classification_dict}
        self._cache: Dict[str, Dict] = {}

    async def classify(
        self,
        schema_info: Dict[str, Any],
        raw_alert: Dict[str, Any],
        fingerprint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Classify alert into OCSF class.

        Args:
            schema_info:  Output of inspect_schema (Tool 1)
            raw_alert:    Full raw alert dict
            fingerprint:  Schema fingerprint (used for in-process cache)

        Returns:
            {class_uid, class_name, category_uid, category_name,
             activity_id, activity_name, reasoning}
        """
        # In-process cache check
        if fingerprint and fingerprint in self._cache:
            logger.debug(f"EventClassifier: local cache HIT [{fingerprint[:8]}]")
            return self._cache[fingerprint]

        # Heuristic fast path
        heuristic = self._try_heuristic(schema_info)
        if heuristic:
            result = heuristic
            result["reasoning"] = "heuristic_match"
        elif self._llm:
            # LLM path
            result = await self._llm_classify(schema_info, raw_alert)
        else:
            logger.warning("No LLM available — falling back to Detection Finding")
            result = dict(DEFAULT_CLASSIFICATION)
            result["reasoning"] = "no_llm_fallback"

        # Cache result
        if fingerprint:
            self._cache[fingerprint] = result
            logger.debug(
                f"EventClassifier: cached [{fingerprint[:8]}] "
                f"→ class_uid={result['class_uid']} ({result['class_name']})"
            )

        return result

    # ── Heuristic ─────────────────────────────────────────────────────────────

    def _try_heuristic(self, schema_info: Dict) -> Optional[Dict]:
        """Rule-based classification from decoder name and key signals."""
        decoder = schema_info.get("decoder_name", "").lower()
        l1 = set(schema_info.get("l1_keys", []))
        source = schema_info.get("source", {})
        data = source.get("data") or {}
        data_str = json.dumps(data).lower()

        for rule, class_uid, activity_id in _HEURISTIC_RULES:
            try:
                if rule(decoder, l1, data_str):
                    cls = OCSF_CLASSES[class_uid]
                    activities = ACTIVITY_IDS.get(class_uid, {})
                    return {
                        "class_uid":     class_uid,
                        "class_name":    cls["name"],
                        "category_uid":  cls["category_uid"],
                        "category_name": cls["category_name"],
                        "activity_id":   activity_id,
                        "activity_name": activities.get(activity_id, "Other"),
                    }
            except Exception:
                continue
        return None

    # ── LLM ───────────────────────────────────────────────────────────────────

    async def _llm_classify(
        self, schema_info: Dict, raw_alert: Dict
    ) -> Dict[str, Any]:
        """Call LLM for OCSF class classification on unknown schemas."""
        source = schema_info.get("source", {})

        # Build compact schema summary for prompt
        schema_summary = (
            f"Estimated source: {schema_info['estimated_source']}\n"
            f"Decoder: {schema_info['decoder_name']}\n"
            f"Top-level keys: {schema_info['l1_keys'][:15]}\n"
            f"Nested keys (data): {schema_info['l2_keys'].get('data', [])[:10]}\n"
            f"Has MITRE IDs: {schema_info['has_mitre_ids']}\n"
            f"Has full_log: {schema_info['has_full_log']}"
        )

        # Sample fields — rule description and key data fields only
        rule = source.get("rule") or {}
        data = source.get("data") or {}
        sample = {
            "rule.description": rule.get("description"),
            "rule.groups": rule.get("groups"),
            "decoder.name": schema_info["decoder_name"],
            "data_preview": {k: v for k, v in list(data.items())[:8]},
            "full_log_preview": str(source.get("full_log", ""))[:300],
        }
        sample_fields = json.dumps(sample, indent=2, default=str)

        prompt = _CLASSIFICATION_PROMPT.format(
            schema_summary=schema_summary,
            sample_fields=sample_fields,
        )

        try:
            raw_response = await self._llm.generate(prompt, max_tokens=150, temperature=0.0)
            parsed = self._parse_llm_response(raw_response)
            if parsed:
                return parsed
        except Exception as e:
            logger.warning(f"LLM classification failed: {e}")

        return dict(DEFAULT_CLASSIFICATION)

    def _parse_llm_response(self, raw: str) -> Optional[Dict]:
        """Parse LLM JSON response into classification dict."""
        try:
            # Strip markdown fences if present
            raw = raw.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]

            data = json.loads(raw)
            class_uid = int(data.get("class_uid", 2004))
            activity_id = int(data.get("activity_id", 1))

            if class_uid not in OCSF_CLASSES:
                logger.warning(f"LLM returned unknown class_uid={class_uid} → fallback 2004")
                class_uid = 2004
                activity_id = 1

            cls = OCSF_CLASSES[class_uid]
            activities = ACTIVITY_IDS.get(class_uid, {})

            return {
                "class_uid":     class_uid,
                "class_name":    cls["name"],
                "category_uid":  cls["category_uid"],
                "category_name": cls["category_name"],
                "activity_id":   activity_id,
                "activity_name": activities.get(activity_id, "Other"),
                "reasoning":     data.get("reasoning", ""),
            }
        except Exception as e:
            logger.warning(f"EventClassifier: LLM response parse error: {e}")
            return None
