import json
from pathlib import Path

BASE = Path(__file__).parent

# ── Test 1: Universal Safety Rules JSON ───────────────────────────────────────
rules = json.load(open(BASE / "data/universal_safety_rules.json", encoding="utf-8"))
assert len(rules) == 7, f"Expected 7 rules, got {len(rules)}"

action_to_rule = {}
for rule in rules:
    for act in rule.get("blocked_actions", []):
        if act not in action_to_rule:
            action_to_rule[act] = rule

hit = action_to_rule.get("delete_logs")
assert hit is not None, "delete_logs must be blocked by UNIVERSAL-001"
assert hit["rule_id"] == "UNIVERSAL-001", f"Got {hit['rule_id']}"
print(f"[OK] delete_logs -> {hit['rule_id']} (enforcement={hit['enforcement']}, route={hit['route_to']})")

hit2 = action_to_rule.get("disable_mfa")
assert hit2 is not None, "disable_mfa must be blocked by UNIVERSAL-005"
assert hit2["rule_id"] == "UNIVERSAL-005"
print(f"[OK] disable_mfa -> {hit2['rule_id']} (enforcement={hit2['enforcement']})")

hit3 = action_to_rule.get("wipe_disk")
assert hit3 is not None and hit3["rule_id"] == "UNIVERSAL-002"
print(f"[OK] wipe_disk   -> {hit3['rule_id']} (route={hit3['route_to']})")

# isolate_host must NOT be universally blocked
assert action_to_rule.get("isolate_host") is None, "isolate_host should not be universally blocked!"
print("[OK] isolate_host -> not universally blocked (safe action, correct)")

print(f"[OK] Total universally blocked action_types: {len(action_to_rule)}")

# ── Test 2: compliance_rules_full.json ────────────────────────────────────────
c_rules = json.load(open(BASE / "data/compliance_rules_full.json", encoding="utf-8"))
assert len(c_rules) == 290, f"Expected 290 rules, got {len(c_rules)}"

from collections import Counter
rule_types = Counter(r["rule_type"] for r in c_rules)
enforcement = Counter(r.get("enforcement", "") for r in c_rules)
frameworks = Counter(r["framework"] for r in c_rules)

print(f"\n[OK] compliance_rules_full.json: {len(c_rules)} rules")
print(f"     Rule types:   {dict(rule_types)}")
print(f"     Enforcement:  {dict(enforcement)}")
print(f"     Frameworks:   {sorted(frameworks.keys())} ({len(frameworks)} total)")

# delete_logs should appear in blocklists
blocklisted = [r for r in c_rules if "delete_logs" in r.get("blocked_actions", [])]
print(f"[OK] delete_logs blocked by {len(blocklisted)} framework rules: {[r['framework']+'/'+r['control_id'] for r in blocklisted]}")

print("\n=== ALL SMOKE TESTS PASSED ===")
