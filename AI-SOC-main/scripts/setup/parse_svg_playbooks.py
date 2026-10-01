"""
SVG Playbook Parser
====================
Extracts flow step text from Mermaid-generated SVG files.
Outputs structured playbook JSON ready for Qdrant ingestion.

SVG format from Lucidchart/Mermaid: text nodes contain step labels,
decision labels (Yes/No), and the trigger node at root.
"""

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Playbook → MITRE ATT&CK technique mapping ─────────────────────────────────
# Derived from playbook filename / content keywords
PLAYBOOK_MITRE_MAP: Dict[str, Dict] = {
    "Ransomware": {
        "mitre_technique_ids": ["T1486", "T1490", "T1489", "T1485"],
        "tactic": "Impact",
        "d3fend_categories": ["Isolate", "Harden", "Detect"],
    },
    "Phishing": {
        "mitre_technique_ids": ["T1566", "T1566.001", "T1566.002", "T1078"],
        "tactic": "Initial Access",
        "d3fend_categories": ["Harden", "Detect", "Isolate"],
    },
    "BEC": {
        "mitre_technique_ids": ["T1566.002", "T1534", "T1114"],
        "tactic": "Collection",
        "d3fend_categories": ["Harden", "Detect"],
    },
    "Data Exfiltration": {
        "mitre_technique_ids": ["T1041", "T1048", "T1567", "T1052"],
        "tactic": "Exfiltration",
        "d3fend_categories": ["Detect", "Isolate"],
    },
    "Malware": {
        "mitre_technique_ids": ["T1059", "T1055", "T1105", "T1204"],
        "tactic": "Execution",
        "d3fend_categories": ["Isolate", "Evict", "Detect"],
    },
    "Endpoint Compromise": {
        "mitre_technique_ids": ["T1059", "T1055", "T1105", "T1204"],
        "tactic": "Execution",
        "d3fend_categories": ["Isolate", "Evict"],
    },
    "Credential Theft": {
        "mitre_technique_ids": ["T1003", "T1110", "T1555", "T1552"],
        "tactic": "Credential Access",
        "d3fend_categories": ["Harden", "Detect"],
    },
    "Identity Compromise": {
        "mitre_technique_ids": ["T1078", "T1003", "T1552"],
        "tactic": "Credential Access",
        "d3fend_categories": ["Harden", "Isolate"],
    },
    "Insider Threat": {
        "mitre_technique_ids": ["T1078", "T1048", "T1530", "T1213"],
        "tactic": "Collection",
        "d3fend_categories": ["Detect", "Harden"],
    },
    "DDoS": {
        "mitre_technique_ids": ["T1498", "T1499", "T1499.001"],
        "tactic": "Impact",
        "d3fend_categories": ["Isolate", "Harden"],
    },
    "Network Intrusion": {
        "mitre_technique_ids": ["T1190", "T1133", "T1021"],
        "tactic": "Initial Access",
        "d3fend_categories": ["Isolate", "Detect"],
    },
    "Zero-Day": {
        "mitre_technique_ids": ["T1190", "T1203", "T1068"],
        "tactic": "Initial Access",
        "d3fend_categories": ["Harden", "Detect", "Isolate"],
    },
    "Vulnerability Exploitation": {
        "mitre_technique_ids": ["T1190", "T1203", "T1068"],
        "tactic": "Execution",
        "d3fend_categories": ["Harden", "Detect"],
    },
    "AD Activity": {
        "mitre_technique_ids": ["T1078", "T1098", "T1136", "T1484"],
        "tactic": "Persistence",
        "d3fend_categories": ["Harden", "Detect"],
    },
    "AWS CloudTrail": {
        "mitre_technique_ids": ["T1562", "T1562.008", "T1530"],
        "tactic": "Defense Evasion",
        "d3fend_categories": ["Detect", "Harden"],
    },
    "AWS GuardDuty": {
        "mitre_technique_ids": ["T1078", "T1530", "T1526"],
        "tactic": "Discovery",
        "d3fend_categories": ["Detect", "Isolate"],
    },
    "Cloudflare": {
        "mitre_technique_ids": ["T1498", "T1190"],
        "tactic": "Impact",
        "d3fend_categories": ["Isolate", "Harden"],
    },
    "CrowdStrike": {
        "mitre_technique_ids": ["T1059", "T1055", "T1486"],
        "tactic": "Execution",
        "d3fend_categories": ["Evict", "Detect"],
    },
    "Cyscale": {
        "mitre_technique_ids": ["T1537", "T1530", "T1562"],
        "tactic": "Exfiltration",
        "d3fend_categories": ["Harden", "Detect"],
    },
    "VPN Connection": {
        "mitre_technique_ids": ["T1133", "T1078"],
        "tactic": "Initial Access",
        "d3fend_categories": ["Harden", "Detect"],
    },
    "ZScaler": {
        "mitre_technique_ids": ["T1071", "T1048", "T1566"],
        "tactic": "Command and Control",
        "d3fend_categories": ["Detect", "Isolate"],
    },
    "User Activity": {
        "mitre_technique_ids": ["T1078", "T1021"],
        "tactic": "Lateral Movement",
        "d3fend_categories": ["Detect"],
    },
}

NOISE_PATTERNS = re.compile(
    r"^(yes|no|maybe|n/a|#graph|@keyframes|font-family|fill:|stroke:|"
    r"animation:|svg|xmlns|true|false|null|undefined|\d+px|\d+\.\d+)$",
    re.IGNORECASE,
)


def extract_text_nodes(svg_path: Path) -> List[str]:
    """
    Extract all meaningful text from SVG XML.
    Filters CSS/styling noise and short tokens.
    """
    tree = ET.parse(svg_path)
    root = tree.getroot()

    texts = []
    for el in root.iter():
        text = (el.text or "").strip()
        if not text or len(text) < 4:
            continue
        # Skip CSS blocks and noise tokens
        if NOISE_PATTERNS.match(text):
            continue
        if "{" in text or "}" in text or ";" in text:
            continue
        texts.append(text)

    return texts


def infer_trigger(texts: List[str], filename: str) -> str:
    """First meaningful non-generic text is usually the trigger node."""
    if texts:
        return texts[0]
    return filename.replace("_", " ").replace("-", " ")


def texts_to_steps(texts: List[str]) -> List[str]:
    """
    Convert raw text nodes to numbered steps.
    Skips the trigger (first node) and decision branches.
    """
    steps = []
    decision_words = {"is", "are", "check", "has", "have", "does", "did"}
    generic_skips = {"yes", "no", "close incident", "close as false positive"}

    for i, text in enumerate(texts[1:], 1):  # skip trigger
        lower = text.lower()
        if lower in generic_skips:
            continue
        # Decision nodes become context notes if they add info
        if any(lower.startswith(w) for w in decision_words):
            steps.append(f"{len(steps)+1}. [Decision] {text}")
        else:
            steps.append(f"{len(steps)+1}. {text}")
    return steps


def match_mitre(filename: str) -> Dict:
    """Match filename to MITRE info using keyword matching."""
    stem = filename.replace(".svg", "").replace("_", " ").replace("-", " ")
    for keyword, info in PLAYBOOK_MITRE_MAP.items():
        if keyword.lower() in stem.lower():
            return info
    # Fallback
    return {
        "mitre_technique_ids": [],
        "tactic": "General",
        "d3fend_categories": ["Detect"],
    }


def parse_svg_playbook(svg_path: Path) -> Optional[Dict]:
    """
    Parse a single SVG playbook file into structured playbook JSON.
    Returns None if parsing yields insufficient content.
    """
    filename = svg_path.stem
    try:
        texts = extract_text_nodes(svg_path)
    except ET.ParseError as e:
        print(f"  ⚠ Parse error for {filename}: {e}")
        return None

    if len(texts) < 3:
        print(f"  ⚠ Too few text nodes ({len(texts)}) in {filename} — skipping")
        return None

    trigger = infer_trigger(texts, filename)
    steps   = texts_to_steps(texts)
    mitre   = match_mitre(filename)

    playbook_id = re.sub(r"[^a-zA-Z0-9]", "_", filename).upper()
    playbook_id = f"PB_{playbook_id[:40]}"

    return {
        "playbook_id":         playbook_id,
        "title":               filename.replace("  ", " — ").replace("_", " "),
        "trigger":             trigger,
        "steps":               steps,
        "mitre_technique_ids": mitre["mitre_technique_ids"],
        "tactic":              mitre["tactic"],
        "d3fend_categories":   mitre["d3fend_categories"],
        "source":              "svg_playbook",
        "chunk_type":          "summary",
        "original_file":       svg_path.name,
    }


def parse_all_svg_playbooks(playbook_dir: Path) -> List[Dict]:
    """
    Parse all SVG files in directory. Returns list of structured playbooks.
    """
    svg_files = sorted(playbook_dir.glob("*.svg"))
    print(f"\nParsing {len(svg_files)} SVG playbooks from {playbook_dir.name}/")

    playbooks = []
    for svg_path in svg_files:
        print(f"  - {svg_path.name}")
        pb = parse_svg_playbook(svg_path)
        if pb:
            playbooks.append(pb)
            print(f"     ✓ {len(pb['steps'])} steps | techniques: {pb['mitre_technique_ids']}")
        else:
            print(f"     ✗ Skipped")

    print(f"\nParsed {len(playbooks)}/{len(svg_files)} playbooks successfully.")
    return playbooks


if __name__ == "__main__":
    playbook_dir = Path(__file__).parent.parent.parent / "Playbooks" / "Playbooks"
    out_path = Path(__file__).parent.parent.parent / "backend" / "services" / "knowledge_base" / "data" / "svg_playbooks.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    playbooks = parse_all_svg_playbooks(playbook_dir)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(playbooks, f, indent=2, ensure_ascii=False)
    print(f"\n✅ Saved {len(playbooks)} playbooks → {out_path.relative_to(playbook_dir.parent.parent.parent)}")
