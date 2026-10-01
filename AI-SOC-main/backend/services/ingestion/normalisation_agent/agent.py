"""
NormalisationAgent — Main Orchestrator
=======================================
Fully autonomous alert normalisation. No hardcoded SIEM-specific logic.

Replace the entire chain:
    log_processor.py → wazuh_mapper.py → sentinelone_mapper.py → ai_mapper.py

With a single call:
    ulf = await agent.normalise(raw_alert)

Flow
----
1. Schema fingerprint
2. Template cache check → fast deterministic path
3. Cache miss / drift → agentic path:
     Tool 1: inspect_schema       (structural analysis)
     Tool 2: classify_event       (OCSF class, heuristic first then LLM)
     Tool 3: normalize_timestamp  (UTC datetime)
     Tool 4: extract_indicators   (IPs, ports, hashes, username, etc.)
     Tool 5: apply_severity_mapping
     Build ULF candidate from tool outputs.
     Tool 6: validate_ocsf        (Pydantic validation)
     → if pass:  Tool 7: run_mitre_enrichment
         → technique_id found:    cache template → return ulf (→ alert_pipeline)
         → technique_id = None:   MITRE DLQ → unmapped_alerts MongoDB → return None
                                  (alert stops here, does NOT reach agentic pipeline)
                                  analyst reviews, adds MITRE tag, resubmits
     → if fail:  LLM correction prompt with errors → retry (max 3 attempts)
     → hard fail (HIGH/CRITICAL no desc): normalisation_dlq — analyst review
     → all retries exhausted: minimal ULF fallback → normalisation_dlq (partial ULF)
     → unrecoverable: normalisation_dlq (nothing returned)

Two separate DLQ collections:
  - normalisation_dlq  : format/validation failures (DLQHandler)
  - unmapped_alerts    : successful ULF but MITRE enrichment produced no technique_id
"""

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .alert_id_generator import generate_alert_id
from .dlq_handler import DLQHandler
from .drift_detector import DriftDetector
from .template_cache import TemplateCache
from .tools.event_classifier import EventClassifier
from .tools.indicator_extractor import extract_indicators
from .tools.mitre_enrichment_tool import run_mitre_enrichment
# asset_meta_lookup moved to alert_pipeline.py (enrichment step)
from .tools.ocsf_validator import validate_ocsf
from .tools.schema_inspector import inspect_schema
from .tools.severity_mapper import apply_severity_mapping
from .tools.timestamp_normalizer import (
    coerce_to_ocsf_time_ms,
    normalize_timestamp,
    ocsf_time_ms,
)

logger = logging.getLogger(__name__)

MAX_RETRIES = 3


class NormalisationAgent:
    """
    Fully agentic alert normaliser.

    Args:
        redis_client:  Async Redis client (aioredis / redis-py asyncio).
                       Optional — falls back to in-process cache if None.
        llm_client:    LLM client with async .generate(prompt, max_tokens, temperature).
                       Must support structured JSON output.
                       Optional — EventClassifier uses heuristics only if None.
        mongo_db:      PyMongo database object for DLQ persistence.
                       Optional — DLQ logs to stderr only if None.
    """

    def __init__(self, redis_client=None, llm_client=None, mongo_db=None):
        self._cache = TemplateCache(redis_client)
        self._drift = DriftDetector()
        self._dlq = DLQHandler(mongo_db=mongo_db, redis_client=redis_client)
        self._classifier = EventClassifier(llm_client)
        self._llm = llm_client
        self._mongo_db = mongo_db  # kept separately for unmapped_alerts DLQ

    # ── Public API ────────────────────────────────────────────────────────────

    async def normalise(self, raw_alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Normalise a raw alert to OCSF ULF.

        Args:
            raw_alert: Raw alert in any format (Wazuh, SentinelOne, ES export, etc.)

        Returns:
            Validated ULF dict with MITRE enrichment, or None if DLQ'd.
        """
        fp = self._fingerprint(raw_alert)

        # ── Fast path: cached template ─────────────────────────────────────────
        template = await self._cache.get(fp)
        if template:
            ulf = self._apply_template(raw_alert, template)
            valid, errors = validate_ocsf(ulf)

            if valid:
                # Check for field drift before accepting
                drifting = self._drift.record(fp, ulf)
                if drifting:
                    logger.info(
                        f"Drift in fields {drifting} for [{fp[:8]}] "
                        "— triggering template refresh"
                    )
                    await self._cache.invalidate(fp)
                    self._drift.clear_drift(fp)
                    # Fall through to agentic path
                else:
                    await self._cache.touch(fp)
                    ulf = await run_mitre_enrichment(ulf)
                    # MITRE DLQ gate — block alert if enrichment found no technique_id
                    if await self._route_to_mitre_dlq_if_needed(ulf, fp):
                        return None
                    logger.info(
                        f"[{fp[:8]}] fast-path normalised → "
                        f"{ulf.get('alert_id')} sev={ulf.get('severity')}"
                    )
                    return ulf
            else:
                logger.warning(
                    f"Template [{fp[:8]}] produced invalid ULF — "
                    f"first error: {errors[0] if errors else '?'} — re-learning"
                )
                await self._cache.invalidate(fp)

        # ── Agentic path ───────────────────────────────────────────────────────
        return await self._agentic_normalise(raw_alert, fp)

    # ── Agentic Path ──────────────────────────────────────────────────────────

    async def _agentic_normalise(
        self, raw_alert: Dict[str, Any], fp: str
    ) -> Optional[Dict[str, Any]]:
        """Full agentic normalisation with tool calls and retry loop."""

        # ── Tool 1: Schema inspection ──────────────────────────────────────────
        schema_info = inspect_schema(raw_alert)
        source = schema_info["source"]

        # ── Tool 2: Event classification (heuristic → LLM if needed) ──────────
        event_class = await self._classifier.classify(schema_info, raw_alert, fp)

        # ── Tool 3: Timestamp normalisation ────────────────────────────────────
        raw_ts = self._find_timestamp(source)
        normalised_ts = normalize_timestamp(raw_ts)

        # ── Tool 4: Indicator extraction ───────────────────────────────────────
        indicators = extract_indicators(source)

        # ── Tool 5: Severity mapping ────────────────────────────────────────────
        severity = apply_severity_mapping(source, schema_info["estimated_source"])

        # ── Build base candidate ────────────────────────────────────────────────
        source_id = raw_alert.get("_id") or source.get("id", str(uuid.uuid4())[:8])
        alert_id = generate_alert_id(source_id, normalised_ts)
        candidate = self._build_candidate(
            raw_alert, source, schema_info, event_class,
            normalised_ts, indicators, severity, alert_id, source_id,
        )

        # ── Retry loop ─────────────────────────────────────────────────────────
        prev_errors: List[str] = []

        for attempt in range(1, MAX_RETRIES + 1):
            if attempt > 1:
                logger.info(f"[{fp[:8]}] retry {attempt}/{MAX_RETRIES}")
                candidate = await self._llm_correct(raw_alert, candidate, prev_errors)

            # ── Tool 6: Validate ───────────────────────────────────────────────
            valid, errors = validate_ocsf(candidate)

            if valid:
                # ── Tool 7: MITRE enrichment ───────────────────────────────────
                ulf = await run_mitre_enrichment(candidate)
                # MITRE DLQ gate — block alert if enrichment found no technique_id
                if await self._route_to_mitre_dlq_if_needed(ulf, fp):
                    return None
                # Cache template after N successes
                await self._cache.record_success(fp, ulf, raw_alert)
                logger.info(
                    f"[{fp[:8]}] agentic normalised (attempt {attempt}) → "
                    f"{alert_id} sev={candidate.get('severity')} "
                    f"class={event_class['class_name']}"
                )
                return ulf

            # Hard fail: HIGH/CRITICAL missing description
            hard_fail = any(
                "must have finding.desc" in e or "HIGH" in e or "CRITICAL" in e
                for e in errors
            )
            if hard_fail:
                logger.error(
                    f"[{fp[:8]}] HARD FAIL: HIGH/CRITICAL alert without description "
                    f"→ DLQ (source_id={source_id!r})"
                )
                await self._dlq.send(
                    raw_alert, candidate, errors,
                    reason="missing_desc_high_severity"
                )
                return None

            prev_errors = errors

        # ── Minimal ULF fallback ────────────────────────────────────────────────
        logger.warning(
            f"[{fp[:8]}] all {MAX_RETRIES} attempts failed — "
            f"building minimal ULF fallback"
        )
        minimal = self._build_minimal_ulf(
            raw_alert, alert_id, normalised_ts, severity, source_id
        )
        min_valid, min_errors = validate_ocsf(minimal)

        if min_valid:
            minimal = await run_mitre_enrichment(minimal)
            # Even the minimal ULF goes through the MITRE DLQ gate
            if await self._route_to_mitre_dlq_if_needed(minimal, fp):
                return None
            await self._dlq.send(
                raw_alert, minimal, prev_errors,
                reason="max_retries_minimal_ulf"
            )
            logger.warning(
                f"[{fp[:8]}] minimal ULF sent to DLQ for review — "
                f"alert still processable with reduced fidelity"
            )
            return minimal     # Return minimal so pipeline can continue

        # Completely unrecoverable
        await self._dlq.send(raw_alert, None, prev_errors, reason="unrecoverable")
        logger.error(f"[{fp[:8]}] UNRECOVERABLE — alert DLQ'd, returning None")
        return None

    # ── Candidate Builder ─────────────────────────────────────────────────────

    def _build_candidate(
        self,
        raw_alert: Dict,
        source: Dict,
        schema_info: Dict,
        event_class: Dict,
        ts: datetime,
        indicators: Dict,
        severity: Dict,
        alert_id: str,
        source_id: str,
    ) -> Dict[str, Any]:
        """Build an initial ULF candidate dict from all tool outputs."""

        rule = source.get("rule") or {}
        agent = source.get("agent") or {}

        # Description from rule, then full_log, then message
        desc = (
            rule.get("description")
            or source.get("message")
            or source.get("full_log", "")[:500]
        )

        # Unmapped fields: preserve unknown top-level keys
        known_top = {
            "rule", "agent", "data", "decoder", "predecoder",
            "@timestamp", "timestamp", "id", "full_log",
            "location", "manager", "input", "GeoLocation",
        }
        unmapped = {
            k: source[k]
            for k in source
            if k not in known_top and source[k] is not None
        }
        if severity.get("raw_severity"):
            unmapped["raw_severity"] = severity["raw_severity"]
        if event_class.get("reasoning"):
            unmapped["ocsf_class_reasoning"] = event_class["reasoning"]

        # finding.uid — deterministic, stable rule identifier. Never a random UUID.
        # Same detection rule firing on different alerts must produce the same uid
        # so alerts can be deduplicated / grouped by rule type.
        # Format: md5(siem_source::rule_id_or_class::description_prefix)[:16]
        _rule_uid_input = (
            f"{schema_info.get('estimated_source', 'unknown')}::"
            f"{rule.get('id') or event_class.get('class_name', 'unknown')}::"
            f"{desc[:80] if desc else 'no_desc'}"
        )
        finding_uid = hashlib.md5(_rule_uid_input.encode()).hexdigest()[:16]

        candidate: Dict[str, Any] = {
            # OCSF class fields
            "class_uid":    event_class["class_uid"],
            "class_name":   event_class["class_name"],
            "category_uid": event_class["category_uid"],
            "category_name":event_class["category_name"],
            "activity_id":  event_class["activity_id"],
            "activity_name":event_class["activity_name"],
            "type_uid":     event_class["class_uid"] * 100 + event_class["activity_id"],
            # Time (OCSF: Unix ms int, not datetime)
            "time":         ocsf_time_ms(ts),
            # Severity
            "severity_id":  severity["severity_id"],
            "severity":     severity["severity"],
            "status":       "New",
            # Metadata
            "metadata": {
                "version":       "1.1.0",
                "product":       schema_info["product"],
                "original_time": ts,
                "logged_time":   datetime.now(timezone.utc),
            },
            # Finding
            "finding": {
                "title": (rule.get("description") or desc[:200] or "Security Alert"),
                "desc":  desc[:1000] if desc else None,
                "uid":   finding_uid,
                "types": [],  # populated by MITRE enrichment (Tool 7)
            },
            # SOAR IDs
            "alert_id":        alert_id,
            "source_alert_id": source_id,
            "siem_source":     schema_info["estimated_source"],
            "ingestion_timestamp": datetime.now(timezone.utc),
            "processing_status":   "normalising",
            # Raw data preservation
            "raw_data": json.dumps(raw_alert, default=str)[:5000],
            "unmapped": unmapped,
        }

        # Endpoints
        src_ep = self._build_endpoint(
            indicators.get("src_ip"),
            indicators.get("src_port"),
            indicators.get("hostname") or agent.get("name"),
        )
        if src_ep:
            candidate["src_endpoint"] = src_ep

        dst_ep = self._build_endpoint(
            indicators.get("dst_ip"),
            indicators.get("dst_port"),
            None,
        )
        if dst_ep:
            candidate["dst_endpoint"] = dst_ep

        # Actor
        if indicators.get("username"):
            candidate["actor"] = {"name": indicators["username"]}

        # Process
        if indicators.get("process_name"):
            candidate["process"] = {
                "name": indicators["process_name"],
                "pid":  indicators.get("pid"),
            }

        # File
        if indicators.get("file_path"):
            candidate["file"] = {"path": indicators["file_path"]}

        # Hashes as observables
        hashes = indicators.get("hashes") or {}
        if hashes:
            candidate["observables"] = [
                {"name": hash_type, "type": "Hash", "value": hash_val}
                for hash_type, hash_val in hashes.items()
            ]

        return candidate

    def _build_minimal_ulf(
        self,
        raw_alert: Dict,
        alert_id: str,
        ts: datetime,
        severity: Dict,
        source_id: str,
    ) -> Dict[str, Any]:
        """Last-resort minimal ULF — only mandatory fields."""
        return {
            "class_uid":    2004,
            "class_name":   "Detection Finding",
            "category_uid": 2,
            "category_name":"Findings",
            "activity_id":  1,
            "activity_name":"Detected",
            "type_uid":     200401,
            "time":         ocsf_time_ms(ts),
            "severity_id":  severity["severity_id"],
            "severity":     severity["severity"],
            "status":       "New",
            "metadata": {
                "version": "1.1.0",
                "product": {"name": "Unknown", "vendor_name": "Unknown"},
            },
            "finding": {
                "title": "Unclassified Security Alert (normalisation fallback)",
                "desc":  "Alert could not be fully normalised. See raw_data for original.",
                "uid":   alert_id,
                "types": [],
            },
            "alert_id":            alert_id,
            "source_alert_id":     source_id,
            "siem_source":         "unknown",
            "ingestion_timestamp": datetime.now(timezone.utc),
            "processing_status":   "minimal_fallback",
            "raw_data":            json.dumps(raw_alert, default=str)[:5000],
            "unmapped":            {"normalisation": "minimal_fallback"},
        }

    # ── Template Application ─────────────────────────────────────────────────

    def _apply_template(
        self, raw_alert: Dict[str, Any], template: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Apply a cached template to a raw alert deterministically.
        No LLM involved. Pure field path lookup + deterministic tools.
        """
        source = raw_alert.get("_source", raw_alert)
        mapped = template.get("mapped", {})

        # Timestamp (always use normalize_timestamp tool)
        raw_ts = self._get_by_path(source, mapped.get("time") or "@timestamp")
        ts = normalize_timestamp(raw_ts)

        # Source ID
        source_id = raw_alert.get("_id") or source.get("id", str(uuid.uuid4())[:8])
        alert_id = generate_alert_id(source_id, ts)

        # Severity
        severity_raw = self._get_by_path(source, mapped.get("severity_field"))
        schema_est = template.get("decoder_hint", "unknown")
        # Rebuild a minimal source dict for severity mapper
        temp_src = {"rule": {"level": severity_raw}} if severity_raw else source
        severity = apply_severity_mapping(temp_src, schema_est)

        # Description
        desc = self._get_by_path(source, mapped.get("description_field"))

        # IPs / endpoints
        src_ip = self._get_by_path(source, mapped.get("src_ip_field"))
        dst_ip = self._get_by_path(source, mapped.get("dst_ip_field"))
        src_port = self._to_int(self._get_by_path(source, mapped.get("src_port_field")))
        dst_port = self._to_int(self._get_by_path(source, mapped.get("dst_port_field")))
        username = self._get_by_path(source, mapped.get("username_field"))
        hostname = self._get_by_path(source, mapped.get("hostname_field"))
        rule_id = self._get_by_path(source, mapped.get("rule_id_field"))

        # Collect unmapped template fields
        unmapped_fields = template.get("unmapped_fields", [])
        unmapped = {}
        for field_path in unmapped_fields:
            val = self._get_by_path(source, field_path)
            if val is not None:
                unmapped[field_path.replace("_source.", "")] = val

        candidate: Dict[str, Any] = {
            "class_uid":    2004,   # Will be corrected from template classification
            "class_name":   "Detection Finding",
            "category_uid": 2,
            "category_name":"Findings",
            "activity_id":  1,
            "activity_name":"Detected",
            "type_uid":     200401,
            "time":         ocsf_time_ms(ts),
            "severity_id":  severity["severity_id"],
            "severity":     severity["severity"],
            "status":       "New",
            "metadata": {
                "version": "1.1.0",
                "product": template.get("product", {"name": "Unknown", "vendor_name": "Unknown"}),
                "original_time": ts,
                "logged_time": datetime.now(timezone.utc),
            },
            "finding": {
                "title": desc[:200] if desc else "Security Alert",
                "desc":  desc[:1000] if desc else None,
                "uid":   rule_id or alert_id,
                "types": [],
            },
            "alert_id":            alert_id,
            "source_alert_id":     source_id,
            "siem_source":         schema_est,
            "ingestion_timestamp": datetime.now(timezone.utc),
            "processing_status":   "normalised",
            "raw_data":            json.dumps(raw_alert, default=str)[:5000],
            "unmapped":            unmapped,
        }

        src_ep = self._build_endpoint(src_ip, src_port, hostname)
        if src_ep:
            candidate["src_endpoint"] = src_ep
        dst_ep = self._build_endpoint(dst_ip, dst_port, None)
        if dst_ep:
            candidate["dst_endpoint"] = dst_ep
        if username:
            candidate["actor"] = {"name": username}

        return candidate

    # ── LLM Correction ───────────────────────────────────────────────────────

    async def _llm_correct(
        self,
        raw_alert: Dict,
        prev_candidate: Dict,
        errors: List[str],
    ) -> Dict[str, Any]:
        """Ask the LLM to fix a failed ULF attempt."""
        if not self._llm:
            return prev_candidate   # No LLM → return unchanged (will retry same)

        prompt = self._build_correction_prompt(raw_alert, prev_candidate, errors)
        try:
            raw_response = await self._llm.generate(prompt, max_tokens=1000, temperature=0.0)
            # Strip markdown code fences
            raw_response = raw_response.strip()
            if raw_response.startswith("```"):
                parts = raw_response.split("```")
                raw_response = parts[1] if len(parts) > 1 else raw_response
                if raw_response.startswith("json"):
                    raw_response = raw_response[4:]
            corrected = json.loads(raw_response)
            # Preserve mandatory fields that LLM must not overwrite
            corrected["alert_id"] = prev_candidate["alert_id"]
            corrected["source_alert_id"] = prev_candidate["source_alert_id"]
            corrected["ingestion_timestamp"] = prev_candidate["ingestion_timestamp"]
            corrected["raw_data"] = prev_candidate["raw_data"]
            # Schema requires `time` as int (epoch ms); LLMs often emit ISO strings or datetimes.
            if "time" in corrected:
                corrected["time"] = coerce_to_ocsf_time_ms(corrected["time"])
            return corrected
        except Exception as e:
            logger.warning(f"LLM correction parse failed: {e}")
            return prev_candidate

    def _build_correction_prompt(
        self, raw_alert: Dict, prev_candidate: Dict, errors: List[str]
    ) -> str:
        from backend.schemas.ulf_schema import UnifiedLogFormat
        schema_fields = list(UnifiedLogFormat.model_fields.keys())
        return (
            "You are correcting a failed OCSF ULF normalisation.\n\n"
            "## Validation Errors (from previous attempt)\n"
            + "\n".join(f"  - {e}" for e in errors)
            + "\n\n## Previous ULF Attempt (failed)\n"
            + json.dumps(prev_candidate, indent=2, default=str)[:2000]
            + "\n\n## Original Raw Alert\n"
            + json.dumps(raw_alert, indent=2, default=str)[:2000]
            + "\n\n## ULF Schema Fields\n"
            + json.dumps(schema_fields)
            + "\n\n## Instructions\n"
            "Fix ONLY the fields that caused validation errors. Keep all other fields unchanged.\n"
            "The 'time' field MUST be an integer: Unix epoch time in MILLISECONDS (OCSF), "
            "e.g. 1730952597000 — not an ISO string and not a datetime object.\n"
            "The 'alert_id' must match format: SOAR-YYYYMMDD-XXXXXXXX (8 hex chars).\n"
            "HIGH/CRITICAL alerts must have finding.desc with at least 10 characters.\n"
            "Respond with corrected ULF JSON only, no explanation.\n"
        )

    # ── MITRE DLQ Gate ────────────────────────────────────────────────────────

    async def _route_to_mitre_dlq_if_needed(self, ulf: Dict[str, Any], fp: str) -> bool:
        """
        Check if MITRE enrichment produced a technique_id.
        If not, write the alert to the `unmapped_alerts` MongoDB collection
        (the MITRE Dead Letter Queue) and return True to signal the caller
        to return None — stopping the alert from flowing downstream.

        The `normalisation_dlq` (DLQHandler) handles format/validation failures.
        This DLQ handles MITRE tagging failures specifically.

        Analyst workflow:
          1. Analyst sees alert in 'Unmapped Alerts' review queue
          2. Manually assigns the correct MITRE technique_id + tactic
          3. Resubmits via POST /normalization/resubmit/mitre/{alert_id}
          4. Alert re-enters the pipeline with the analyst-provided mapping
          5. Successful mapping feeds back into enrichment pattern library

        Returns:
            True if alert was DLQ'd (caller should return None)
            False if technique_id is present (alert should continue)
        """
        enrichment = ulf.get("enrichments", {}).get("mitre", {})
        technique_id = enrichment.get("technique_id")
        technique_confidence = float(enrichment.get("technique_confidence", 0.0))

        if technique_id:
            return False  # MITRE enrichment succeeded — let alert flow

        # All 3 layers failed to produce a technique_id
        alert_id = ulf.get("alert_id", "unknown")
        mapping_method = enrichment.get("mapping_method", "unknown")
        error_detail = enrichment.get("error", "")

        logger.warning(
            f"[{fp[:8]}] MITRE enrichment: no technique_id after all 3 layers "
            f"(method={mapping_method}, conf={technique_confidence:.2f}) "
            f"— routing to unmapped_alerts DLQ"
        )

        dlq_doc = {
            "alert_id":             alert_id,
            "schema_fingerprint":   fp,
            "normalised_ulf":       ulf,
            "mitre_enrichment":     enrichment,
            "mapping_method":       mapping_method,
            "technique_confidence": technique_confidence,
            "dlq_reason":           "no_technique_id",
            "error_detail":         error_detail,
            "queued_at":            datetime.now(timezone.utc).isoformat(),
            "status":               "pending_analyst_review",
            "analyst_id":           None,
            "analyst_mapping":      None,   # analyst fills: {technique_id, tactic_id, ...}
            "reviewed_at":          None,
        }

        try:
            if self._mongo_db is not None:
                self._mongo_db.unmapped_alerts.insert_one(dlq_doc)
                logger.info(
                    f"Alert {alert_id} written to unmapped_alerts DLQ "
                    f"(fingerprint={fp[:8]})"
                )
            else:
                logger.error(
                    f"No MongoDB client — cannot write {alert_id} to unmapped_alerts DLQ. "
                    f"Alert will be silently dropped."
                )
        except Exception as e:
            logger.error(f"Failed to write {alert_id} to unmapped_alerts DLQ: {e}")

        return True  # Signal caller to return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _fingerprint(self, raw_alert: Dict) -> str:
        """Compute deep schema fingerprint: L1 + L2 keys + decoder.name + _index."""
        src = raw_alert.get("_source", raw_alert)
        l1 = sorted(src.keys())
        l2 = {
            k: sorted((src.get(k) or {}).keys())
            for k in ["rule", "agent", "data", "decoder", "predecoder"]
            if isinstance(src.get(k), dict)
        }
        sig = json.dumps({
            "l1": l1,
            "l2": l2,
            "decoder": (src.get("decoder") or {}).get("name", ""),
            "index": raw_alert.get("_index", "")[:20],
        }, sort_keys=True)
        return hashlib.md5(sig.encode()).hexdigest()

    def _find_timestamp(self, source: Dict) -> Optional[str]:
        """Try common timestamp field names in priority order."""
        for field in ["@timestamp", "timestamp", "event_time", "time", "datetime"]:
            val = source.get(field)
            if val:
                return str(val)
        return None

    def _get_by_path(self, source: Dict, path: Optional[str]) -> Optional[Any]:
        """Resolve a dotted field path (e.g. '_source.rule.description') from source dict."""
        if not path:
            return None
        # Strip _source. prefix if present
        path = path.replace("_source.", "")
        parts = path.split(".")
        val = source
        for p in parts:
            if isinstance(val, dict):
                val = val.get(p)
            else:
                return None
        return val if val != "" else None

    def _build_endpoint(
        self,
        ip: Optional[str],
        port: Optional[int],
        hostname: Optional[str],
    ) -> Optional[Dict]:
        if not ip and not hostname:
            return None
        ep = {}
        if ip:
            ep["ip"] = ip
        if port:
            ep["port"] = port
        if hostname:
            ep["hostname"] = hostname
        return ep

    def _to_int(self, val) -> Optional[int]:
        if val is None:
            return None
        try:
            return int(val)
        except (ValueError, TypeError):
            return None
