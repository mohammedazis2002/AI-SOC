#!/usr/bin/env python3
"""Fix HIPAA encoding issue and verify all 290 canonical control IDs match."""
import json
from pathlib import Path

DATA_DIR = Path(__file__).parent

# ── 1. Fix HIPAA canonical file encoding ─────────────────────────────────────
hipaa_path = DATA_DIR / "compliance_hipaa_canonical.json"
# Read as text, replace mojibake, write back clean
content = hipaa_path.read_text(encoding='utf-8', errors='replace')
content_fixed = content.replace('\u00c2\u00a7', '\u00a7')  # Â§ → §
content_fixed = content_fixed.replace('Â§', '§')            # legacy fallback
hipaa_path.write_text(content_fixed, encoding='utf-8')

# Reload and check
with open(hipaa_path, encoding="utf-8") as f:
    hipaa_rules = json.load(f)

print(f"[HIPAA] Loaded {len(hipaa_rules)} rules")
for r in hipaa_rules[:3]:
    print(f"  control_id = {r['control_id']!r}")

# ── 2. Re-run merge to regenerate compliance_rules_full.json ─────────────────
CANONICAL_FILES = [
    "compliance_pci_dss_canonical.json",
    "compliance_iso27001_canonical.json",
    "compliance_gdpr_canonical.json",
    "compliance_hipaa_canonical.json",
    "compliance_nist_800_53_canonical.json",
    "compliance_soc2_canonical.json",
    "compliance_cis_v8_canonical.json",
    "compliance_sebi_canonical.json",
    "compliance_dpdp_canonical.json",
    "compliance_iso_42001_canonical.json",
    "compliance_nist_csf_canonical.json",
]

all_rules = []
for fname in CANONICAL_FILES:
    with open(DATA_DIR / fname, encoding="utf-8") as f:
        rules = json.load(f)
    all_rules.extend(rules)
    print(f"  ✓ {fname}: {len(rules)} rules")

with open(DATA_DIR / "compliance_rules_full.json", "w", encoding="utf-8") as f:
    json.dump(all_rules, f, indent=2, ensure_ascii=False)

print(f"\n✅ compliance_rules_full.json: {len(all_rules)} rules total")

# ── 3. Canonical ID verification ─────────────────────────────────────────────
written_ids = set(r["control_id"] for r in all_rules)

CANONICAL = {
    # PCI-DSS (35)
    "10.2.1","10.2.2","10.2.4","10.2.5","10.2.6","10.2.7","10.5.1","10.7.2","10.7.3",
    "11.4.7","12.10.1","12.10.2","12.10.4","12.10.5","12.10.6","12.10.7","6.3.3","6.4.3",
    "7.1.1","7.2.5","7.2.6","8.2.6","8.2.8","8.3.10","3.4","3.5.1","4.2","5.2.1","5.3.2",
    "9.9.1","9.9.3","1.4.1","1.4.5","2.2.7","2.3.2",
    # GDPR (45)
    "Art. 33(1)","Art. 33(2)","Art. 33(3)(a)","Art. 33(3)(b)","Art. 33(3)(c)","Art. 33(5)",
    "Art. 34(1)","Art. 34(3)(a)","Art. 32(1)(a)","Art. 32(1)(b)","Art. 32(1)(c)","Art. 32(1)(d)",
    "Art. 32(2)","Art. 25(1)","Art. 25(2)","Art. 5(1)(e)","Art. 5(1)(f)","Art. 6","Art. 9",
    "Art. 15","Art. 17","Art. 18","Art. 20","Art. 21","Art. 35","Art. 37","Art. 44","Art. 46",
    "Recital 49","Recital 75","Recital 83","Recital 87","Art. 30","Art. 24","Art. 28","Art. 47",
    "Art. 58","Art. 77","Art. 82","Art. 83","Art. 12","Art. 13","Art. 14","Art. 38","Art. 40",
    # HIPAA (28)
    "§164.312(a)(1)","§164.312(a)(2)(i)","§164.312(a)(2)(ii)","§164.312(a)(2)(iii)",
    "§164.312(a)(2)(iv)","§164.312(b)","§164.312(c)(1)","§164.312(c)(2)","§164.312(d)",
    "§164.312(e)(1)","§164.312(e)(2)(i)","§164.312(e)(2)(ii)","§164.308(a)(1)(i)",
    "§164.308(a)(1)(ii)(A)","§164.308(a)(1)(ii)(B)","§164.308(a)(1)(ii)(C)",
    "§164.308(a)(1)(ii)(D)","§164.308(a)(6)(i)","§164.308(a)(6)(ii)","§164.308(a)(7)(i)",
    "§164.308(a)(7)(ii)(A)","§164.308(a)(7)(ii)(B)","§164.308(a)(7)(ii)(C)",
    "§164.308(a)(7)(ii)(D)","§164.308(a)(7)(ii)(E)","§164.310(a)(1)","§164.310(d)(1)",
    "§164.316(b)(2)(i)",
    # ISO 27001 (32)
    "A.5.24","A.5.25","A.5.26","A.5.27","A.5.28","A.16.1.5","A.16.1.6","A.16.1.7",
    "A.8.15","A.8.16","A.8.17","A.5.33","A.5.34","A.5.10","A.8.2","A.8.3","A.8.5",
    "A.8.10","A.8.11","A.8.12","A.8.13","A.8.14","A.7.2","A.7.4","A.6.8","A.8.25",
    "A.8.26","A.8.28","A.8.32","A.5.23","A.5.30","A.8.6",
    # NIST 800-53 (42)
    "IR-1","IR-2","IR-3","IR-4","IR-5","IR-6","IR-7","IR-8","IR-9","IR-10",
    "AU-2","AU-3","AU-4","AU-6","AU-9","AU-11","AU-12","SI-3","SI-4","SI-5","SI-7","SI-12",
    "AC-2","AC-3","AC-4","AC-6","AC-17","CM-3","CM-5","CP-2","CP-4","CP-9","CP-10",
    "RA-3","RA-5","SA-11","SC-7","SC-8","SC-12","SC-13","SC-28","PE-3",
    # SOC 2 (18)
    "CC6.1","CC6.2","CC6.3","CC6.6","CC6.7","CC7.1","CC7.2","CC7.3","CC7.4","CC7.5",
    "CC8.1","CC9.1","A1.1","A1.2","A1.3","C1.1","C1.2","PI1.4",
    # CIS v8 (25)
    "17.1","17.2","17.3","17.4","17.5","17.6","17.7","17.8","17.9",
    "8.1","8.2","8.3","8.5","8.10","8.11","6.1","6.2","6.5","6.8","5.1","5.2","5.3",
    "10.1","11.1","11.5",
    # SEBI (15)
    "4.1.1","4.1.2","4.1.3","4.1.4","4.2.1","4.2.2","4.2.3","4.3.1","4.3.2","4.3.3",
    "4.4.1","4.4.2","4.4.3","4.5.1","4.5.2",
    # DPDP (12)
    "Sec 8(1)","Sec 8(2)","Sec 8(3)","Sec 8(4)","Sec 8(5)","Sec 8(6)",
    "Sec 10","Sec 11","Sec 12","Sec 6","Sec 7","Sec 9",
    # ISO 42001 (20)
    "8.1.1","8.1.2","8.1.3","7.2.1","7.2.2","7.2.3","8.2.1","8.2.2","8.2.3",
    "6.2.1","6.2.2","6.2.3","9.1.1","9.1.2","9.1.3","5.1.1","5.1.2","7.3.1","7.3.2","10.1.1",
    # NIST CSF 2.0 (18)
    "DE.AE-1","DE.AE-2","DE.AE-3","DE.CM-1","DE.CM-7","RS.RP-1","RS.CO-2","RS.CO-3",
    "RS.AN-1","RS.AN-2","RS.AN-3","RS.MI-1","RS.MI-2","RS.IM-1","RC.RP-1","RC.IM-1",
    "RC.CO-3","ID.SC-4",
}

missing = CANONICAL - written_ids
print(f"\n📋 FINAL VERIFICATION")
print(f"  Canonical required: {len(CANONICAL)}")
print(f"  Written in JSON:    {len(written_ids)}")
print(f"  Missing:            {len(missing)}")
if missing:
    for m in sorted(missing):
        print(f"    ⛔ {m!r}")
else:
    print("  ✅ ALL 290 CANONICAL CONTROL IDs COVERED!")

# also show rule_type breakdown
from collections import Counter
rt = Counter(r["rule_type"] for r in all_rules)
print("\n  Rule type breakdown:")
for k, v in rt.most_common():
    print(f"    {k}: {v}")
