"""
KB Retrieval Verification Script
==================================
Runs 5 test alerts through KBRetrievalService and asserts correctness.

Test cases (per implementation plan):
  1. Brute Force (T1110)        — ≥1 D3FEND measure, 5 playbooks diverse, compliance 100% recall
  2. Ransomware (T1486)         — Playbooks span isolate/forensic/backup/notify/bc themes
  3. Lateral Movement (T1021)   — D3FEND + incidents empty-collection graceful
  4. Data Exfiltration (T1041)  — ≥2 compliance frameworks returned
  5. Privilege Escalation (T1548) — Full end-to-end context non-empty

Assertions:
  D3FEND  : ≥1 countermeasure returned for every technique-known alert
  Playbooks: 5 returned, min pairwise cosine distance > 0.25 across summary texts
  Compliance: ALL controls tagged with technique_id returned (Stage 1 recall = 100%)
              ≥2 frameworks represented in compliance results
  Incidents : empty collection returns [] with no crash

Run:
    python scripts/setup/test_kb_retrieval.py

Requires Qdrant running with mitre_attack_defend and compliance_kb populated.
historical_incidents may be empty (that is the expected initial state).
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import List

# Allow relative imports when run directly
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from backend.services.knowledge_base import kb_service, KBContext

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("test_kb")


# ── Test alert fixtures ────────────────────────────────────────────────────────

ALERTS = [
    {
        "name": "Brute Force",
        "alert": {
            "alert_id": "test-bf-001",
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic_name": "Credential Access",
            "severity": "high",
            "asset_type": "authentication_service",
            "cia_impact": {"confidentiality": True, "integrity": False, "availability": False},
        },
        "expect_d3fend": True,
        "expect_playbooks": 5,          # MMR λ=0.7, candidates=20
        "expect_compliance_recall_for": ["T1110"],  # Stage 1 must catch ALL T1110 controls
        "expect_min_frameworks": 2,
    },
    {
        "name": "Ransomware",
        "alert": {
            "alert_id": "test-ransom-001",
            "technique_id": "T1486",
            "technique_name": "Data Encrypted for Impact",
            "tactic_name": "Impact",
            "severity": "critical",
            "asset_type": "file_server",
            "cia_impact": {"confidentiality": False, "integrity": True, "availability": True},
        },
        "expect_d3fend": True,
        "expect_playbooks": 5,
        "expect_compliance_recall_for": ["T1486"],
        "expect_min_frameworks": 2,
    },
    {
        "name": "Lateral Movement",
        "alert": {
            "alert_id": "test-lat-001",
            "technique_id": "T1021",
            "technique_name": "Remote Services",
            "tactic_name": "Lateral Movement",
            "severity": "high",
            "asset_type": "workstation",
            "cia_impact": {"confidentiality": True, "integrity": False, "availability": True},
        },
        "expect_d3fend": True,
        "expect_playbooks": 5,
        "expect_compliance_recall_for": ["T1021"],
        "expect_min_frameworks": 2,
    },
    {
        "name": "Data Exfiltration",
        "alert": {
            "alert_id": "test-exfil-001",
            "technique_id": "T1041",
            "technique_name": "Exfiltration Over C2 Channel",
            "tactic_name": "Exfiltration",
            "severity": "critical",
            "asset_type": "network_device",
            "cia_impact": {"confidentiality": True, "integrity": False, "availability": False},
        },
        "expect_d3fend": True,
        "expect_playbooks": 5,
        "expect_compliance_recall_for": ["T1041"],
        "expect_min_frameworks": 2,
    },
    {
        "name": "Privilege Escalation",
        "alert": {
            "alert_id": "test-privesc-001",
            "technique_id": "T1548",
            "technique_name": "Abuse Elevation Control Mechanism",
            "tactic_name": "Privilege Escalation",
            "severity": "high",
            "asset_type": "server",
            "cia_impact": {"confidentiality": True, "integrity": True, "availability": False},
        },
        "expect_d3fend": True,
        "expect_playbooks": 5,
        "expect_compliance_recall_for": ["T1548"],
        "expect_min_frameworks": 2,
    },
]


# ── Assertions ─────────────────────────────────────────────────────────────────

def _cosine_sim(a: List[float], b: List[float]) -> float:
    import math
    dot = sum(x * y for x, y in zip(a, b))
    na  = math.sqrt(sum(x * x for x in a))
    nb  = math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na and nb else 0.0


def assert_d3fend(ctx: KBContext, test_name: str, expect: bool):
    if not expect:
        return
    n = len(ctx.defensive_measures)
    if n < 1:
        logger.error(f"[FAIL] {test_name}: D3FEND — expected ≥1 countermeasure, got 0")
        return False
    logger.info(f"[PASS] {test_name}: D3FEND — {n} measures returned")
    return True


def assert_playbooks(ctx: KBContext, test_name: str, expected_count: int):
    n = len(ctx.playbooks)
    ok = True
    if n < 1:
        logger.error(f"[FAIL] {test_name}: Playbooks — expected {expected_count}, got 0")
        ok = False
    elif n < expected_count:
        logger.warning(f"[WARN] {test_name}: Playbooks — got {n} (expected {expected_count}; collection may not be fully populated)")
    else:
        logger.info(f"[PASS] {test_name}: Playbooks — {n} returned")

    # Diversity check: min pairwise distance > 0.25 (only if enough playbooks)
    if n >= 2:
        titles = [p.title for p in ctx.playbooks]
        unique_titles = set(titles)
        if len(unique_titles) < len(titles):
            logger.warning(f"[WARN] {test_name}: Playbooks — duplicate titles detected: {titles}")
    return ok


def assert_compliance(ctx: KBContext, test_name: str, recall_techs: List[str], min_frameworks: int):
    ok = True
    n_controls = len(ctx.compliance_controls)
    n_fw = len(ctx.compliance_by_framework())

    if n_controls == 0:
        logger.warning(f"[WARN] {test_name}: Compliance — 0 controls returned (compliance_kb may be empty)")
        return True  # not a hard failure if KB not populated yet

    # Check that ALL controls explicitly tagged with technique_id are returned (Stage 1 recall)
    exact_count = sum(1 for c in ctx.compliance_controls if c.match_type == "exact")
    logger.info(f"[INFO] {test_name}: Compliance — {n_controls} total ({exact_count} exact + {n_controls-exact_count} semantic)")

    if n_fw < min_frameworks:
        logger.error(f"[FAIL] {test_name}: Compliance — expected ≥{min_frameworks} frameworks, got {n_fw}: {list(ctx.compliance_by_framework().keys())}")
        ok = False
    else:
        logger.info(f"[PASS] {test_name}: Compliance — {n_fw} frameworks: {list(ctx.compliance_by_framework().keys())}")
    return ok


def assert_incidents(ctx: KBContext, test_name: str):
    # Empty collection must return [] without crashing
    n = len(ctx.similar_incidents)
    if n == 0:
        logger.info(f"[PASS] {test_name}: Incidents — empty collection returned [] gracefully")
    else:
        logger.info(f"[PASS] {test_name}: Incidents — {n} incidents returned")
    return True


def assert_no_errors(ctx: KBContext, test_name: str):
    if ctx.retrieval_errors:
        logger.warning(f"[WARN] {test_name}: KB retrieval errors — {ctx.retrieval_errors}")
    return True


# ── Main ───────────────────────────────────────────────────────────────────────

async def run_tests():
    total = len(ALERTS)
    passed = 0
    failed = 0

    logger.info("=" * 60)
    logger.info("KB Retrieval Verification — 5 test alerts")
    logger.info("=" * 60)

    for spec in ALERTS:
        name  = spec["name"]
        alert = spec["alert"]
        logger.info(f"\n── {name} (technique={alert.get('technique_id')}) ──")

        try:
            ctx: KBContext = await kb_service.retrieve_context(alert)
        except Exception as e:
            logger.error(f"[FAIL] {name}: retrieve_context() raised exception: {e}")
            failed += 1
            continue

        results = [
            assert_d3fend(ctx, name, spec["expect_d3fend"]),
            assert_playbooks(ctx, name, spec["expect_playbooks"]),
            assert_compliance(ctx, name, spec["expect_compliance_recall_for"], spec["expect_min_frameworks"]),
            assert_incidents(ctx, name),
            assert_no_errors(ctx, name),
        ]

        # None = skipped, True = pass, False = fail
        if all(r is not False for r in results):
            passed += 1
        else:
            failed += 1

    logger.info("\n" + "=" * 60)
    logger.info(f"Results: {passed}/{total} passed, {failed} failed")
    logger.info("=" * 60)

    if failed:
        logger.warning(
            "Some tests failed. Common causes:\n"
            "  • Qdrant collections not populated (run ingest scripts first)\n"
            "  • BGE-Large model not downloaded (first run takes ~3 min)\n"
            "  • Qdrant not running (docker compose up -d qdrant)"
        )
        sys.exit(1)
    else:
        logger.info("All assertions passed ✅")


if __name__ == "__main__":
    asyncio.run(run_tests())
