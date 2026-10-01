"""
Template Cache
==============
Redis-backed schema fingerprint → ULF mapping template cache.

Each template stores the structural mapping learned by the LLM on first encounter
of a schema variant. Subsequent alerts with the same schema fingerprint are
normalised deterministically using this cached mapping — no LLM call needed.

Cache lifecycle:
  - Written after WARMUP_THRESHOLD successes for a fingerprint (prevents poisoning)
  - TTL is sliding (refreshed on every hit): templates for active SIEMs never expire
  - Templates for decommissioned SIEMs auto-evict after TTL_SECONDS
"""

import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

TTL_SECONDS = 30 * 24 * 3600   # 30 days sliding
WARMUP_THRESHOLD = 3            # cache after N validated successes


class TemplateCache:
    """
    Redis-backed cache of schema fingerprint → ULF mapping templates.

    Template structure:
        {
            "mapped": {
                "time":              "_source.@timestamp",
                "severity_field":    "_source.rule.level",
                "src_ip_field":      "_source.data.srcip",
                "description_field": "_source.rule.description",
                ...
            },
            "unmapped_fields": ["_source.GeoLocation", "_source.predecoder.timestamp"],
            "product":       {"name": "Wazuh", "vendor_name": "Wazuh Inc"},
            "source_id_field": "_id",
            "decoder_hint":  "wazuh-firewall",
            "hit_count":     0,
            "success_count": 0
        }
    """

    def __init__(self, redis_client=None):
        self._redis = redis_client
        self._local: Dict[str, Dict] = {}   # in-process fallback if Redis unavailable

    # ── Public API ────────────────────────────────────────────────────────────

    async def get(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        """Return cached template for fingerprint, or None on cache miss."""
        key = self._key(fingerprint)
        try:
            if self._redis:
                raw = await self._redis.get(key)
                if raw:
                    logger.debug(f"Template cache HIT  [{fingerprint[:8]}]")
                    await self._redis.expire(key, TTL_SECONDS)     # sliding TTL
                    return json.loads(raw)
        except Exception as e:
            logger.warning(f"Redis get failed: {e} — using local cache")

        local = self._local.get(fingerprint)
        if local:
            logger.debug(f"Template local HIT  [{fingerprint[:8]}]")
        return local

    async def record_success(
        self,
        fingerprint: str,
        ulf: Dict[str, Any],
        raw_alert: Dict[str, Any],
        template: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Record a successful normalisation.
        Builds and stores template after WARMUP_THRESHOLD successes.
        If a template already exists, merges any new field mappings (superset).
        """
        key_count = f"{self._key(fingerprint)}:warmup"
        try:
            count = 0
            if self._redis:
                count = int(await self._redis.incr(key_count) or 0)
                await self._redis.expire(key_count, TTL_SECONDS)
            else:
                self._local.setdefault(f"{fingerprint}:count", 0)
                self._local[f"{fingerprint}:count"] += 1
                count = self._local[f"{fingerprint}:count"]

            if count >= WARMUP_THRESHOLD:
                # Build template from current successful ULF + raw alert
                new_template = self._extract_template(ulf, raw_alert)
                existing = await self.get(fingerprint)
                if existing:
                    merged = self._merge_templates(existing, new_template)
                else:
                    merged = new_template
                await self._store(fingerprint, merged)
                logger.info(
                    f"Template committed for [{fingerprint[:8]}] "
                    f"(success #{count}) — {len(merged.get('mapped', {}))} field mappings"
                )
        except Exception as e:
            logger.warning(f"Template record_success failed: {e}")

    async def touch(self, fingerprint: str) -> None:
        """Refresh sliding TTL on a cache hit."""
        try:
            if self._redis:
                await self._redis.expire(self._key(fingerprint), TTL_SECONDS)
        except Exception:
            pass

    async def invalidate(self, fingerprint: str) -> None:
        """Force invalidation — called by DriftDetector on repeated None fields."""
        key = self._key(fingerprint)
        try:
            if self._redis:
                await self._redis.delete(key)
                logger.info(f"Template invalidated [{fingerprint[:8]}] — drift detected")
        except Exception as e:
            logger.warning(f"Template invalidation failed: {e}")
        self._local.pop(fingerprint, None)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _key(self, fp: str) -> str:
        return f"norm:template:{fp}"

    async def _store(self, fingerprint: str, template: Dict) -> None:
        key = self._key(fingerprint)
        raw = json.dumps(template)
        try:
            if self._redis:
                await self._redis.setex(key, TTL_SECONDS, raw)
        except Exception as e:
            logger.warning(f"Redis setex failed: {e} — storing locally only")
        self._local[fingerprint] = template

    def _extract_template(
        self, ulf: Dict[str, Any], raw_alert: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Derive a field-path mapping template from a validated ULF and the source alert.
        Stores only the mapping paths, not the actual values.
        """
        src = raw_alert.get("_source", raw_alert)

        # Reverse-lookup: for each ULF field, find the source path that produced it
        mapped = {}
        mapped["time"] = self._find_path(src, ["@timestamp", "timestamp", "event_time"])
        mapped["description_field"] = self._find_path(src, ["rule.description", "message", "full_log"])
        mapped["severity_field"] = self._find_path(src, ["rule.level", "severity", "level"])
        mapped["src_ip_field"] = self._find_path(src, ["data.srcip", "data.src_ip", "network.srcip"])
        mapped["dst_ip_field"] = self._find_path(src, ["data.dstip", "data.dst_ip", "network.dstip"])
        mapped["src_port_field"] = self._find_path(src, ["data.srcport", "data.src_port"])
        mapped["dst_port_field"] = self._find_path(src, ["data.dstport", "data.dst_port"])
        mapped["username_field"] = self._find_path(src, ["data.user", "data.srcuser", "data.username"])
        mapped["hostname_field"] = self._find_path(src, ["agent.name", "host.hostname", "predecoder.hostname"])
        mapped["rule_id_field"] = self._find_path(src, ["rule.id", "rule_id"])
        mapped["source_id_field"] = "_id" if raw_alert.get("_id") else None

        # Product metadata (stable per decoder)
        decoder = (src.get("decoder") or {}).get("name", "unknown")
        product = _infer_product(decoder)

        # Identify fields not mapped to any ULF slot (to push to unmapped)
        all_l1 = set(src.keys())
        known_l1 = {"rule", "agent", "data", "decoder", "predecoder", "@timestamp",
                    "timestamp", "id", "full_log", "location", "manager", "input", "GeoLocation"}
        unmapped_fields = [k for k in all_l1 if k not in known_l1]

        return {
            "mapped": {k: v for k, v in mapped.items() if v},
            "unmapped_fields": unmapped_fields,
            "product": product,
            "decoder_hint": decoder,
            "hit_count": 0,
        }

    def _merge_templates(self, existing: Dict, new: Dict) -> Dict:
        """Merge new template into existing — new wins on conflict, superset union."""
        merged = dict(existing)
        merged["mapped"] = {**existing.get("mapped", {}), **new.get("mapped", {})}
        merged["unmapped_fields"] = list(
            set(existing.get("unmapped_fields", [])) | set(new.get("unmapped_fields", []))
        )
        merged["product"] = new.get("product") or existing.get("product")
        merged["decoder_hint"] = new.get("decoder_hint") or existing.get("decoder_hint")
        return merged

    def _find_path(self, src: Dict, candidates: list) -> Optional[str]:
        """Find the first candidate dotted path that exists in src and has a value."""
        for path in candidates:
            parts = path.split(".")
            val = src
            for p in parts:
                if isinstance(val, dict):
                    val = val.get(p)
                else:
                    val = None
                    break
            if val is not None and val != "":
                return path
        return None


def _infer_product(decoder_name: str) -> Dict[str, str]:
    """Map decoder name to OCSF product metadata."""
    name = decoder_name.lower()
    if "wazuh" in name:
        return {"name": "Wazuh", "vendor_name": "Wazuh Inc"}
    if "sentinelone" in name or "sentinel" in name:
        return {"name": "SentinelOne", "vendor_name": "SentinelOne Inc"}
    if "crowdstrike" in name:
        return {"name": "Falcon", "vendor_name": "CrowdStrike"}
    if "paloalto" in name or "pan" in name:
        return {"name": "PAN-OS", "vendor_name": "Palo Alto Networks"}
    if "fortinet" in name or "fortigate" in name:
        return {"name": "FortiGate", "vendor_name": "Fortinet"}
    if "cisco" in name:
        return {"name": "Cisco ASA", "vendor_name": "Cisco"}
    if "cloudtrail" in name or "aws" in name:
        return {"name": "CloudTrail", "vendor_name": "Amazon Web Services"}
    if "zscaler" in name:
        return {"name": "Zscaler", "vendor_name": "Zscaler Inc"}
    return {"name": "Unknown", "vendor_name": "Unknown"}
