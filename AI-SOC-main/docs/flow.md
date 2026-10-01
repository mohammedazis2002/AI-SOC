wazuh
↓
wazuh.py router
↓
wazuh_service.py
↓
NormalisationAgent ← OCSF/ULF + MITRE enrichment (Tool 7)
↓
AlertProcessor.process_alert() ← further enrichment + storage + queuing
↓
┌──────┴────────────────────────────────────┐
│ 1. Correlation (quick + deep) │
│ 2. Threat Intel (9 providers parallel) │
│ 3. Asset Meta lookup │
│ 4. Asset Risk scoring │
│ 5. False Positive detection │
│ 6. FP Queue assignment │
│ 7. Store → alerts_processed │
│ 8. Triage scoring (0-100) │
│ 9. Redis queue (priority/standard) │
└───────────────────────────────────────────┘
