"""
Configuration Management for Agentic SOAR
Centralized configuration for all agents and services
"""

from typing import Dict, Any
import os


class AgenticConfig:
    """Central configuration for agentic SOAR system"""
    
    # ==================== ML SERVICES ====================
    ML_SERVICES = {
        "anomaly_detection": {
            "url": "http://localhost:5001",
            "endpoint": "/predict",
            "timeout": 10
        },
        "attack_stage": {
            "url": "http://localhost:5002",
            "endpoint": "/predict",
            "timeout": 10
        },
        "attack_forecasting": {
            "url": "http://localhost:5003",
            "endpoint": "/predict",
            "timeout": 10
        },
        "fp_detection": {
            "url": "http://localhost:5004",
            "endpoint": "/predict",
            "timeout": 10
        },
        "asset_risk": {
            "url": "http://localhost:5005",
            "endpoint": "/predict",
            "timeout": 10
        },
        "root_cause": {
            "url": "http://localhost:5006",
            "endpoint": "/predict",
            "timeout": 10
        }
    }
    
    # ==================== LLM CONFIGURATION ====================
    LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://localhost:11434")
    
    LLM_PRIMARY = "llama3.1:70b"      # Complex reasoning
    LLM_SECONDARY = "llama3.1:8b"     # Action planning
    LLM_FALLBACK = "phi3:mini"        # Emergency fallback
    
    # ==================== QDRANT CONFIGURATION ====================
    QDRANT_HOST = os.getenv("QDRANT_HOST", "localhost")
    QDRANT_PORT = int(os.getenv("QDRANT_PORT", "6333"))
    
    QDRANT_COLLECTIONS = {
        "historical_incidents": "incident_embeddings",
        "playbooks": "playbook_embeddings",
        "compliance_knowledge": "compliance_kb",
        "framework_rules": "compliance_rules"
    }
    
    # ==================== MONGODB CONFIGURATION ====================
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    MONGO_DB = "soar_agentic"
    
    MONGO_COLLECTIONS = {
        "incidents": "incidents",          # Full incident data with all enrichments
        "audit_logs": "audit_logs",        # Complete audit trail (includes agent metrics)
        "cold_storage": "incident_archive" # 90-day compliance retention
    }
    
    # Review queue is in Redis (real-time queue management)
    # Agent metrics are embedded in audit_logs (no separate collection needed)
    
    # ==================== REDIS CONFIGURATION ====================
    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_DB = int(os.getenv("REDIS_DB", "0"))
    
    # ==================== DECISION ENGINE THRESHOLDS ====================
    
    # Auto-execute thresholds
    AUTO_EXECUTE_SAFETY_THRESHOLD = 0.85  # Minimum safety score
    AUTO_EXECUTE_IMPACT_THRESHOLD = 0.30   # Maximum impact score
    
    # Action whitelists/blacklists
    AUTO_EXECUTE_WHITELIST = [
        "block_ip",
        "isolate_user",
        "disable_account",
        "quarantine_file",
        "block_domain",
        "revoke_token"
    ]
    
    AUTO_EXECUTE_BLACKLIST = [
        "shutdown_production",
        "delete_data",
        "modify_firewall_core_rules",
        "drop_database",
        "system_reboot"
    ]
    
    # ==================== COMPLIANCE FRAMEWORKS ====================
    # 10 Core Frameworks for Indian Financial Sector + Global Standards
    COMPLIANCE_FRAMEWORKS = [
        "GDPR",           # EU General Data Protection Regulation
        "HIPAA",          # Health Insurance Portability and Accountability Act
        "DPDP",           # India Digital Personal Data Protection Act 2023
        "ISO27001",       # Information Security Management
        "ISO42001",       # AI Management System (AI Ethics)
        "NIST",           # NIST Cybersecurity Framework
        "CIS18",          # CIS Critical Security Controls (18 controls)
        "PCI_DSS",        # Payment Card Industry Data Security Standard
        "CIA_TRIAD",      # Confidentiality, Integrity, Availability
        "SEBI_CSCRF",     # SEBI Cyber Security and Cyber Resilience Framework
        "SOC2"            # Service Organization Control 2 (additional)
    ]
    
    # ==================== AGENT CONFIGURATION ====================
    
    # Maximum iterations to prevent infinite loops
    # Justification: 2-phase reasoning + retries + complexity = sufficient for 99% of cases
    # If exhausted, escalate to manual review
    MAX_ITERATIONS = 10
    
    # Timeout for entire pipeline (seconds)
    # TARGET: <3 minutes (180 seconds) for automated response
    # Realistic breakdown with optimization:
    #   Supervisor (2s) + Reasoning P1 (30s) + Planning (45s parallel) 
    #   + Reasoning P2 (30s) + Remediation (20s) + Auditor (20s) + Decision (3s)
    #   = ~150 seconds typical case
    # Buffer for variability: 30s
    # TOTAL: 180 seconds (3 minutes)
    PIPELINE_TIMEOUT = 180  # 3 minutes (hard limit for automation)
    
    # Agent-specific timeouts (in seconds)
    # OPTIMIZED FOR <3 MINUTE PIPELINE TARGET
    #
    # Optimization strategies:
    # 1. Use streaming LLM responses (early termination)
    # 2. Aggressive prompt engineering (concise outputs)
    # 3. Parallel ML service calls (Planning agent)
    # 4. Qdrant search optimization (indexed collections)
    # 5. Cached compliance rules (reduce repeated searches)
    #
    # Justification:
    # - Supervisor: 2s (priority assessment, no LLM - fast)
    # - Reasoning: 30s (Llama 3.1 70B with streaming ~15-20s + Qdrant ~5s + logs ~5s)
    # - Planning: 45s (6 ML services PARALLEL, max wait ~30s + aggregation ~10s + buffer)
    # - Remediation: 20s (Llama 3.1 8B streaming ~8-10s + Qdrant ~5s + customization ~5s)
    # - Auditor: 20s (Fast compliance checks ~10s + LLM solutions streaming ~8-10s)
    # - Decision: 3s (Pure rule-based logic, report generation from state)
    #
    # Total typical: ~120-150s (well under 3 min target)
    # Total worst-case: 2+30+45+30+20+20+3 = 150s (2.5 minutes)
    AGENT_TIMEOUTS = {
        "supervisor": 2,    # Optimized: simple logic
        "reasoning": 30,    # Optimized: streaming LLM + concurrent searches
        "planning": 45,     # Optimized: parallel ML calls with aggressive timeout
        "remediation": 20,  # Optimized: streaming LLM + cached playbooks
        "auditor": 20,      # Optimized: cached rules + streaming solutions
        "decision": 3       # Optimized: rule-based, no LLM
    }
    
    # ==================== PRIORITY CLASSIFICATION ====================
    # P1-P4 Priority Levels with SLA targets
    # Updated for automated SOAR (aggressive targets)
    
    PRIORITY_CRITERIA = {
        "P1": {
            "name": "Critical",
            "sla_response": "<15 minutes",
            "sla_resolution": "1 hour",
            "criteria": [
                "Severity: Critical",
                "Active data breach or ransomware",
                "Critical asset compromised",
                "Production system down",
                "Imminent threat to business continuity",
                "Regulatory compliance violation in progress"
            ],
            "examples": [
                "Active ransomware encryption",
                "Database server compromised",
                "DDoS taking down production"
            ]
        },
        "P2": {
            "name": "High",
            "sla_response": "<30 minutes",
            "sla_resolution": "2 hours",
            "criteria": [
                "Severity: High",
                "Confirmed attack in progress",
                "High-value asset targeted",
                "Lateral movement detected",
                "Privilege escalation attempt"
            ],
            "examples": [
                "APT lateral movement",
                "Admin credential theft",
                "Command & control communication"
            ]
        },
        "P3": {
            "name": "Medium",
            "sla_response": "<45 minutes",
            "sla_resolution": "4 hours",
            "criteria": [
                "Severity: Medium",
                "Suspicious activity detected",
                "Potential compromise",
                "Policy violation",
                "Anomalous behavior"
            ],
            "examples": [
                "Phishing attempt detected",
                "Unusual login location",
                "Port scan activity"
            ]
        },
        "P4": {
            "name": "Low",
            "sla_response": "<60 minutes",
            "sla_resolution": "8 hours",
            "criteria": [
                "Severity: Low",
                "Information gathering",
                "Minor policy violation",
                "Low-confidence alert",
                "Non-critical informational"
            ],
            "examples": [
                "Failed login attempts (threshold not exceeded)",
                "Reconnaissance activity",
                "Configuration drift"
            ]
        }
    }
    
    # ==================== LOGGING ====================
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # ==================== HELPER METHODS ====================
    
    @classmethod
    def get_ml_service_url(cls, service_name: str) -> str:
        """Get full URL for ML service"""
        if service_name not in cls.ML_SERVICES:
            raise ValueError(f"Unknown ML service: {service_name}")
        
        service = cls.ML_SERVICES[service_name]
        return f"{service['url']}{service['endpoint']}"
    
    @classmethod
    def get_all_ml_service_names(cls) -> list:
        """Get list of all available ML service names"""
        return list(cls.ML_SERVICES.keys())
    
    @classmethod
    def get_qdrant_collection(cls, collection_type: str) -> str:
        """Get Qdrant collection name"""
        if collection_type not in cls.QDRANT_COLLECTIONS:
            raise ValueError(f"Unknown collection type: {collection_type}")
        return cls.QDRANT_COLLECTIONS[collection_type]
    
    @classmethod
    def is_action_auto_executable(cls, action_type: str) -> bool:
        """Check if action can be auto-executed"""
        if action_type in cls.AUTO_EXECUTE_BLACKLIST:
            return False
        if action_type in cls.AUTO_EXECUTE_WHITELIST:
            return True
        return False  # Default to manual review if not in whitelist


# Create global config instance
config = AgenticConfig()
