"""
DEPRECATED — Rule-Based MITRE Technique Prediction
====================================================
This module has been superseded by MITREEnrichmentService
(backend/services/enrichment/mitre_enrichment_service.py), which uses
sentence-transformers + Qdrant for semantic matching across all 691
MITRE ATT&CK techniques and sub-techniques.

This file is kept for reference only. It is no longer imported anywhere.
"""


import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class MITREPredictor:
    """
    Rule-based MITRE technique prediction based on alert content patterns
    Fallback for alerts without existing MITRE data
    """
    
    def __init__(self):
        """Initialize prediction rules"""
        self.rules = self._build_prediction_rules()
    
    def _build_prediction_rules(self) -> List[Dict]:
        """Build pattern matching rules for MITRE prediction"""
        return [
            # Credential Access Techniques
            {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "patterns": [
                    "brute force", "brute-force", "multiple failed", 
                    "failed password", "failed login", "authentication failed",
                    "too many attempts", "account locked", "password spray"
                ],
                "confidence": 0.95
            },
            {
                "technique_id": "T1078",
                "technique_name": "Valid Accounts",
                "patterns": [
                    "valid account", "successful login after", "compromised credentials",
                    "stolen credentials", "credential reuse"
                ],
                "confidence": 0.85
            },
            {
                "technique_id": "T1003",
                "technique_name": "OS Credential Dumping",
                "patterns": [
                    "mimikatz", "credential dump", "lsass", "sam database",
                    "password hash", "ntds.dit"
                ],
                "confidence": 0.95
            },
            
            # Execution Techniques
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "patterns": [
                    "powershell", "cmd.exe", "bash", "sh -c", "/bin/sh",
                    "script execution", "command line", "wscript", "cscript"
                ],
                "confidence": 0.90
            },
            {
                "technique_id": "T1204",
                "technique_name": "User Execution",
                "patterns": [
                    "malicious file executed", "suspicious executable", 
                    "user executed", ".exe downloaded"
                ],
                "confidence": 0.80
            },
            
            # Initial Access Techniques
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "patterns": [
                    "sql injection", "xss", "rce", "remote code execution",
                    "exploit attempt", "vulnerability exploit", "web shell"
                ],
                "confidence": 0.90
            },
            {
                "technique_id": "T1133",
                "technique_name": "External Remote Services",
                "patterns": [
                    "vpn login", "rdp connection", "ssh connection from external",
                    "remote desktop", "external access"
                ],
                "confidence": 0.85
            },
            
            # Discovery Techniques
            {
                "technique_id": "T1595",
                "technique_name": "Active Scanning",
                "patterns": [
                    "port scan", "network scan", "reconnaissance", "nmap",
                    "scanning activity", "probe"
                ],
                "confidence": 0.95
            },
            {
                "technique_id": "T1083",
                "technique_name": "File and Directory Discovery",
                "patterns": [
                    "directory listing", "file enumeration", "dir command",
                    "ls -la", "find command"
                ],
                "confidence": 0.80
            },
            
            # Lateral Movement
            {
                "technique_id": "T1021",
                "technique_name": "Remote Services",
                "patterns": [
                    "psexec", "wmi", "remote execution", "lateral movement",
                    "remote service", "smb", "rdp"
                ],
                "confidence": 0.85
            },
            
            # Command and Control
            {
                "technique_id": "T1071",
                "technique_name": "Application Layer Protocol",
                "patterns": [
                    "c2 communication", "command and control", "beacon",
                    "suspicious http", "dns tunneling", "covert channel"
                ],
                "confidence": 0.85
            },
            
            # Persistence
            {
                "technique_id": "T1053",
                "technique_name": "Scheduled Task/Job",
                "patterns": [
                    "scheduled task", "cron job", "at command", 
                    "task scheduler", "schtasks", "persistence mechanism"
                ],
                "confidence": 0.90
            },
            {
                "technique_id": "T1136",
                "technique_name": "Create Account",
                "patterns": [
                    "new account created", "user added", "account creation",
                    "useradd", "net user /add"
                ],
                "confidence": 0.90
            },
            
            # Defense Evasion
            {
                "technique_id": "T1070",
                "technique_name": "Indicator Removal",
                "patterns": [
                    "log cleared", "event log deleted", "history cleared",
                    "wevtutil", "clear-eventlog", "rm -rf /var/log"
                ],
                "confidence": 0.95
            },
            {
                "technique_id": "T1562",
                "technique_name": "Impair Defenses",
                "patterns": [
                    "antivirus disabled", "firewall disabled", "security tool",
                    "tamper protection", "defender disabled"
                ],
                "confidence": 0.95
            },
            
            # Exfiltration
            {
                "technique_id": "T1041",
                "technique_name": "Exfiltration Over C2 Channel",
                "patterns": [
                    "data exfiltration", "large outbound transfer", 
                    "suspicious upload", "data theft"
                ],
                "confidence": 0.85
            },
            
            # Impact
            {
                "technique_id": "T1486",
                "technique_name": "Data Encrypted for Impact",
                "patterns": [
                    "ransomware", "encryption", "files encrypted",
                    ".encrypted", "ransom note"
                ],
                "confidence": 0.98
            },
            {
                "technique_id": "T1490",
                "technique_name": "Inhibit System Recovery",
                "patterns": [
                    "shadow copy deleted", "backup deleted", "vssadmin delete",
                    "recovery disabled", "bcdedit"
                ],
                "confidence": 0.95
            }
        ]
    
    def predict(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict MITRE techniques from alert content
        
        Args:
            alert: Alert dictionary (ULF or raw)
            
        Returns:
            {
                "predicted_techniques": ["T1110", "T1078"],
                "confidence": 0.85,
                "matched_rules": [...]
            }
        """
        # Gather all text content from alert
        text_content = self._extract_text_content(alert)
        
        # Match against rules
        matched_rules = []
        for rule in self.rules:
            if self._matches_rule(text_content, rule):
                matched_rules.append(rule)
        
        if not matched_rules:
            return {
                "predicted_techniques": [],
                "confidence": 0.0,
                "matched_rules": [],
                "method": "rule_based"
            }
        
        # Extract unique technique IDs
        techniques = list(set([r["technique_id"] for r in matched_rules]))
        
        # Calculate overall confidence (average of matched rules)
        avg_confidence = sum([r["confidence"] for r in matched_rules]) / len(matched_rules)
        
        return {
            "predicted_techniques": techniques,
            "confidence": round(avg_confidence, 2),
            "matched_rules": [
                {
                    "technique_id": r["technique_id"],
                    "technique_name": r["technique_name"],
                    "confidence": r["confidence"]
                }
                for r in matched_rules
            ],
            "method": "rule_based"
        }
    
    def _extract_text_content(self, alert: Dict[str, Any]) -> str:
        """Extract all searchable text from alert"""
        texts = []
        
        # Finding title and description
        if "finding" in alert:
            texts.append(str(alert["finding"].get("title", "")))
            texts.append(str(alert["finding"].get("desc", "")))
        
        # Raw log data
        if "raw_data" in alert:
            texts.append(str(alert["raw_data"]))
        
        # Actions and recommendations
        texts.append(str(alert.get("action", "")))
        texts.append(str(alert.get("recommended_action", "")))
        
        # Process information
        if "process" in alert:
            texts.append(str(alert["process"].get("name", "")))
            texts.append(str(alert["process"].get("cmd_line", "")))
        
        # File information
        if "file" in alert:
            texts.append(str(alert["file"].get("path", "")))
            texts.append(str(alert["file"].get("name", "")))
        
        # Combine and lowercase
        combined = " ".join(texts).lower()
        return combined
    
    def _matches_rule(self, text_content: str, rule: Dict) -> bool:
        """Check if text content matches rule patterns"""
        for pattern in rule["patterns"]:
            if pattern.lower() in text_content:
                return True
        return False


# Module-level singleton
_predictor = None

def get_mitre_predictor() -> MITREPredictor:
    """Get singleton predictor instance"""
    global _predictor
    if _predictor is None:
        _predictor = MITREPredictor()
    return _predictor
