import json
from collections import defaultdict

with open("compliance_rules_full.json") as f:
    rules = json.load(f)

fw_counts = defaultdict(lambda: defaultdict(int))
for r in rules:
    fw_counts[r["framework"]]["total"] += 1
    fw_counts[r["framework"]][r["rule_type"]] += 1

print(f"TOTAL RULES: {len(rules)}")
print()
header = f"{'Framework':<30} {'Total':<8} {'blocklist':<12} {'req_action':<12} {'req_approval':<14} {'sequence':<10} {'cond_block':<10}"
print(header)
print("-" * 96)
grand = defaultdict(int)
for fw, counts in sorted(fw_counts.items()):
    print(f"{fw:<30} {counts['total']:<8} {counts['action_blocklist']:<12} {counts['required_action']:<12} {counts['required_approval']:<14} {counts['action_sequence']:<10} {counts['conditional_block']:<10}")
    for k, v in counts.items():
        grand[k] += v
print("-" * 96)
print(f"{'TOTAL':<30} {grand['total']:<8} {grand['action_blocklist']:<12} {grand['required_action']:<12} {grand['required_approval']:<14} {grand['action_sequence']:<10} {grand['conditional_block']:<10}")
