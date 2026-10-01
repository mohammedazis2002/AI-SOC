"""
Auditor Agent Knowledge Base
Centralized definitions for CIA Triad mappings and Compliance Controls.
Expanded to cover ~75 Standard OCSF Event Classes.
"""

from typing import Dict, List, Any

# =================================================================
# CIA TRIAD MAPPINGS (OCSF Classes)
# =================================================================
# Maps OCSF Class IDs to primary CIA impact and Risk Description
# Based on OCSF v1.1 Categories:
# 1xxx: System, 2xxx: Findings, 3xxx: IAM, 4xxx: Network, 5xxx: Discovery, 6xxx: Application

CIA_IMPACT_MAPPING = {
    # --- 1xxx: SYSTEM ACTIVITY (Integrity/Confidentiality) ---
    "1001": {"cia": "confidentiality", "risk": "File Acess (Potential Exfiltration)"},
    "1002": {"cia": "integrity", "risk": "Kernel Modification (Rootkit Risk)"},
    "1003": {"cia": "integrity", "risk": "Memory Modification (Injection)"},
    "1004": {"cia": "integrity", "risk": "Module Load (Malicious Code)"},
    "1005": {"cia": "integrity", "risk": "Process Activity (Execution)"},
    "1006": {"cia": "integrity", "risk": "Scheduled Job (Persistence)"},
    "1007": {"cia": "integrity", "risk": "Process Activity (Execution)"}, # Alternate
    "1008": {"cia": "integrity", "risk": "Service/Daemon Modification"},
    
    # --- 2xxx: SECURITY FINDINGS (Mixed) ---
    "2001": {"cia": "integrity", "risk": "Security Finding (General)"},
    "2002": {"cia": "integrity", "risk": "Vulnerability Found"},
    "2003": {"cia": "confidentiality", "risk": "Compliance Violation"},
    "2004": {"cia": "integrity", "risk": "Malware Detected"},
    "2005": {"cia": "availability", "risk": "Network Anomaly (DDoS/Scan)"},
    
    # --- 3xxx: IAM (Confidentiality/Integrity) ---
    "3001": {"cia": "integrity", "risk": "Account Change (Privilege Escalation)"},
    "3002": {"cia": "confidentiality", "risk": "Authentication Failed (Brute Force)"},
    "3003": {"cia": "confidentiality", "risk": "Authentication Success (Compromise)"},
    "3004": {"cia": "integrity", "risk": "Entity Management"},
    "3005": {"cia": "integrity", "risk": "Group Management"},
    "3006": {"cia": "confidentiality", "risk": "Access Privilege Usage"},
    
    # --- 4xxx: NETWORK ACTIVITY (Availability/Confidentiality) ---
    "4001": {"cia": "availability", "risk": "Network Traffic (Denial of Service?)"},
    "4002": {"cia": "confidentiality", "risk": "Network Connection (Exfiltration)"},
    "4003": {"cia": "confidentiality", "risk": "DNS Query (C2 / Tunneling)"},
    "4004": {"cia": "availability", "risk": "DHCP Activity"},
    "4005": {"cia": "confidentiality", "risk": "RDP Activity (Remote Access)"},
    "4006": {"cia": "confidentiality", "risk": "SMB Activity (Lateral Movement)"},
    "4007": {"cia": "confidentiality", "risk": "SSH Activity (Remote Access)"},
    "4008": {"cia": "confidentiality", "risk": "FTP Activity (Data Transfer)"},
    "4009": {"cia": "confidentiality", "risk": "Email Activity (Phishing/Exfil)"},
    "4010": {"cia": "confidentiality", "risk": "Tunneling Activity"},
    
    # --- 5xxx: DISCOVERY (Confidentiality) ---
    "5001": {"cia": "confidentiality", "risk": "Inventory Info Gathering"},
    "5002": {"cia": "confidentiality", "risk": "Config Discovery"},
    "5003": {"cia": "confidentiality", "risk": "User Discovery"},
    "5004": {"cia": "confidentiality", "risk": "Network Discovery"},
    "5005": {"cia": "confidentiality", "risk": "Service Discovery"},
    "5006": {"cia": "confidentiality", "risk": "OSINT Gathering"},

    # --- 6xxx: APPLICATION (Integrity/Availability) ---
    "6001": {"cia": "availability", "risk": "Application Lifecycle (Crash/Stop)"},
    "6002": {"cia": "integrity", "risk": "API Activity (Abuse)"},
    "6003": {"cia": "integrity", "risk": "Web Resource Access"},
    "6004": {"cia": "integrity", "risk": "Datastore Activity (SQLi)"},
    "6005": {"cia": "integrity", "risk": "File Hosting Activity"},
    
    # --- FALLBACKS ---
    "Exfiltration": {"cia": "confidentiality", "risk": "Data Loss"},
    "Ransomware": {"cia": "integrity", "risk": "Data Encryption"},
    "Denial of Service": {"cia": "availability", "risk": "Service Disruption"},
}

# =================================================================
# CIA CONTEXT RULES (Overrides)
# =================================================================
# Specific conditions that override the default Class-based risk.
# Logic: If (class_id matches AND keyword in message), apply override.

CIA_CONTEXT_RULES = [
    # Auth Failure: Usually Confidentiality (Compromise attempt), but High Volume/Blocked = Availability (Lockout)
    {
        "class_id": "3002", 
        "keywords": ["lockout", "blocked", "flood", "denial"], 
        "cia": "availability", 
        "risk": "Account Lockout (DoS prevention)"
    },
    # Process Activity: Default Integrity, but "Dump" = Confidentiality
    {
        "class_id": "1005", 
        "keywords": ["dump", "lsass", "credential", "steal"], 
        "cia": "confidentiality", 
        "risk": "Credential Dumping"
    },
    # File Activity: Default Integrity, but "Read" sensitive = Confidentiality
    {
        "class_id": "1001",
        "keywords": ["read", "exfil", "copy"],
        "cia": "confidentiality",
        "risk": "Data Exfiltration"
    },
    # Network Traffic: Default Avail (DoS), but "C2" = Confidentiality
    {
        "class_id": "4001",
        "keywords": ["command and control", "c2", "beacon"],
        "cia": "confidentiality",
        "risk": "C2 Communication"
    }
]

# =================================================================
# COMPLIANCE FRAMEWORK CONTROLS (EXPANDED)
# =================================================================
# Maps Framework -> Context -> Controls

COMPLIANCE_KB = {
    "GDPR": {
        "context": ["has_pii", "involves_personal_data", "geo_eu"],
        "controls": {
            "breach_notify": {
                "id": "Art. 33",
                "name": "Data Breach Notification",
                "requirement": "Notify supervisory authority within 72 hours.",
                "required_action": "notify_dpo",
                "description": "Trigger breach notification protocol for DPO."
            },
            "security": {
                "id": "Art. 32",
                "name": "Security of Processing",
                "requirement": "Implement encryption and pseudonymisation.",
                "required_action": "encrypt_data",
                "description": "Ensure data at rest/transit is encrypted."
            },
            "rights": {
                "id": "Art. 17",
                "name": "Right to Erasure",
                "requirement": "Erase personal data without undue delay if required.",
                "required_action": "delete_records",
                "description": "Remove compromised PII if retention is not justified."
            }
        }
    },
    "PCI_DSS": {
        "context": ["has_pci", "involves_card_data"],
        "controls": {
            "containment": {
                "id": "Req 12.10.1",
                "name": "Incident Response - Containment",
                "requirement": "Immediate isolation of compromised systems.",
                "required_action": "isolate",
                "description": "Isolate host from the Cardholder Data Environment (CDE)."
            },
            "evidence": {
                "id": "Req 10.7",
                "name": "Audit Trail Retention",
                "requirement": "Retain audit trail history for at least one year.",
                "required_action": "preserve_logs",
                "description": "Secure logs to prevent tampering."
            },
            "account_lockout": {
                "id": "Req 8.1.6",
                "name": "Lockout Mechanisms",
                "requirement": "Lock out user IDs after not more than 10 failed attempts.",
                "required_action": "disable_user",
                "description": "Disable compromised or brute-forced accounts."
            }
        }
    },
    "HIPAA": {
        "context": ["has_phi", "involves_health_data"],
        "controls": {
            "encryption": {
                "id": "§164.312(a)(2)(iv)",
                "name": "Encryption",
                "requirement": "Encrypt EPHI at rest and in transit.",
                "required_action": "encrypt_phi",
                "description": "Apply encryption to exposed health records."
            },
            "sanction": {
                "id": "§164.308(a)(1)(ii)(C)",
                "name": "Sanction Policy",
                "requirement": "Apply sanctions to workforce members for non-compliance.",
                "required_action": "suspend_account",
                "description": "Suspend internal accounts involved in unauthorized access."
            },
            "access_control": {
                "id": "§164.312(a.1)",
                "name": "Access Control",
                "requirement": "Allow access only to those persons or software programs that have been granted access rights.",
                "required_action": "revoke_access",
                "description": "Revoke unauthorized access rights immediately."
            }
        }
    },
    "NIST_CSF": {
        "context": ["critical_infrastructure", "federal_system"],
        "controls": {
            "mitigation": {
                "id": "RS.MI-1",
                "name": "Mitigation",
                "requirement": "Incidents are contained.",
                "required_action": "contain_threat",
                "description": "Execute containment strategy."
            },
            "analysis": {
                "id": "RS.AN-1",
                "name": "Analysis",
                "requirement": "Notifications from detection systems are investigated.",
                "required_action": "investigate",
                "description": "Perform forensic analysis."
            }
        }
    }
}

# =================================================================
# SAFE ACTIONS
# =================================================================
SAFE_ACTIONS = {
    "containment": [
        "isolate_host", "block_ip", "disable_user", "quarantine_file",
        "contain_threat", "suspend_account", "lock_account"
    ],
    "analysis": [
        "enrich_data", "scan_system", "dump_memory", "check_logs",
        "investigate", "get_process_list", "verify_hash"
    ],
    "remediation": [
        "delete_file", "kill_process", "reset_password", "patch_system",
        "encrypt_data", "encrypt_phi", "delete_records", "revoke_access"
    ],
    "recovery": [
        "restore_backup", "restart_service", "unblock_ip", "enable_user"
    ],
    "compliance": [
        "notify_dpo", "preserve_logs", "generate_report"
    ]
}

# Actions that ALWAYS require manual approval
CRITICAL_ACTIONS = ["shutdown_server", "wipe_disk", "bulk_password_reset", "firewall_rule_delete"]
