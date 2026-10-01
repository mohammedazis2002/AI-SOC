"""
False Positive Feature Extractor

Extracts 25 features from OCSF ULF alerts for FP prediction.
Designed to work with minimal historical data (cold start friendly).
"""

import logging
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, Any, List
from collections import Counter
import numpy as np

logger = logging.getLogger(__name__)


class FPFeatureExtractor:
    """
    Extract features for false positive prediction from OCSF alerts
    
    Feature Categories:
    - Alert Characteristics (8): severity, frequency, keywords, confidence
    - User/Asset Context (6): trusted users, dev environments, scanners
    - Temporal Patterns (5): business hours, periodicity, timing
    - Historical Feedback (6): past FP rates, analyst actions
    """
    
    # FP indicator keywords
    FP_KEYWORDS = [
        'test', 'testing', 'dev', 'development', 'staging', 'sandbox', 'demo',
        'scanner', 'scan', 'nmap', 'nessus', 'qualys', 'burpsuite',
        'monitor', 'monitoring', 'check', 'health', 'probe',
        'localhost', '127.0.0.1', 'scheduled', 'automated'
    ]
    
    # Known vulnerability scanner processes/tools
    SCANNER_INDICATORS = [
        'nmap', 'nessus', 'qualys', 'openvas', 'acunetix', 'burp',
        'metasploit', 'nikto', 'sqlmap', 'w3af', 'zap'
    ]
    
    def __init__(self, db_client=None):
        """
        Args:
            db_client: MongoDB client for historical queries
        """
        self.db = db_client
    
    def extract(self, alert: Dict[str, Any]) -> np.ndarray:
        """
        Extract all 25 features from alert
        
        Args:
            alert: OCSF ULF alert dictionary
            
        Returns:
            Feature vector (25,)
        """
        features = []
        
        # === Alert Characteristics (8 features) ===
        features.append(self._get_severity(alert))
        features.append(self._get_class_uid(alert))
        features.append(self._get_alert_frequency_score(alert))
        features.append(self._has_fp_keywords(alert))
        features.append(self._get_threat_intel_score(alert))
        features.append(self._get_confidence_score(alert))
        features.append(self._is_noisy_rule(alert))
        features.append(self._get_mitre_tactic_encoded(alert))
        
        # === User/Asset Context (6 features) ===
        features.append(self._user_is_known_good(alert))
        features.append(self._user_is_service_account(alert))
        features.append(self._asset_is_scanner(alert))
        features.append(self._asset_is_dev_env(alert))
        features.append(self._source_is_internal(alert))
        features.append(self._get_user_privilege_level(alert))
        
        # === Temporal Patterns (5 features) ===
        features.append(self._is_business_hours(alert))
        features.append(self._is_weekend(alert))
        features.append(self._get_time_of_day_entropy(alert))
        features.append(self._is_repeated_pattern(alert))
        features.append(self._get_time_since_last_similar(alert))
        
        # === Historical Feedback (6 features) ===
        features.append(self._get_similar_fp_count(alert, days=7))
        features.append(self._get_similar_tp_count(alert, days=7))
        features.append(self._get_fp_rate_for_rule(alert))
        features.append(self._get_analyst_dismissed_count(alert))
        features.append(self._get_avg_investigation_time(alert))
        features.append(self._get_escalation_rate(alert))
        
        return np.array(features, dtype=float)
    
    # === Alert Characteristics ===
    
    def _get_severity(self, alert: Dict) -> float:
        """Alert severity (0-1 normalized)"""
        severity_id = alert.get('severity_id', 2)
        return severity_id / 4.0  # Normalize 1-4 to 0.25-1.0
    
    def _get_class_uid(self, alert: Dict) -> float:
        """OCSF class UID (encoded)"""
        class_uid = alert.get('class_uid', 0)
        # Normalize large numbers
        return min(class_uid / 10000.0, 1.0)
    
    def _get_alert_frequency_score(self, alert: Dict) -> float:
        """How frequently this rule fires (0-1, high = more frequent = likely FP)"""
        if self.db is None:
            return 0.0
        
        rule_id = alert.get('unmapped', {}).get('wazuh_rule_id')
        if not rule_id:
            return 0.0
        
        # Count alerts from this rule in last 24 hours
        cutoff = datetime.now() - timedelta(hours=24)
        cutoff_ms = int(cutoff.timestamp() * 1000)
        
        count = self.db.alerts.count_documents({
            'unmapped.wazuh_rule_id': rule_id,
            'time': {'$gte': cutoff_ms}
        })
        
        # Normalize: >100 alerts/day = very noisy
        return min(count / 100.0, 1.0)
    
    def _has_fp_keywords(self, alert: Dict) -> float:
        """Contains FP indicator keywords (0-1)"""
        title = alert.get('finding', {}).get('title', '').lower()
        desc = alert.get('finding', {}).get('desc', '').lower()
        text = f"{title} {desc}"
        
        # Count keyword matches
        matches = sum(1 for keyword in self.FP_KEYWORDS if keyword in text)
        
        # Normalize: 3+ keywords = strong FP indicator
        return min(matches / 3.0, 1.0)
    
    def _get_threat_intel_score(self, alert: Dict) -> float:
        """Threat intelligence score (0-1, low = more likely FP)"""
        enrichments = alert.get('enrichments', {})
        threat_intel = enrichments.get('threat_intel', {})
        
        # Average of available TI sources
        scores = []
        
        if 'abuseipdb' in threat_intel:
            scores.append(threat_intel['abuseipdb'].get('confidence', 0) / 100.0)
        
        if 'virustotal' in threat_intel:
            vt = threat_intel['virustotal']
            if vt.get('total', 0) > 0:
                scores.append(vt.get('malicious', 0) / vt.get('total', 1))
        
        return np.mean(scores) if scores else 0.0
    
    def _get_confidence_score(self, alert: Dict) -> float:
        """Alert confidence from source (0-1)"""
        # Wazuh: use rule level
        rule_level = alert.get('unmapped', {}).get('wazuh_rule_level', 5)
        return min(rule_level / 15.0, 1.0)
    
    def _is_noisy_rule(self, alert: Dict) -> float:
        """Rule is on known noisy list (1.0 or 0.0)"""
        if self.db is None:
            return 0.0
        
        rule_id = alert.get('unmapped', {}).get('wazuh_rule_id')
        if not rule_id:
            return 0.0
        
        # Check noisy rules collection
        noisy = self.db.noisy_rules.find_one({'rule_id': rule_id})
        
        return 1.0 if noisy else 0.0
   
    def _get_mitre_tactic_encoded(self, alert: Dict) -> float:
        """Encoded MITRE tactic (0-1)"""
        tactic_encoding = {
            'reconnaissance': 0.0, 'resource_development': 0.067,
            'initial_access': 0.133, 'execution': 0.2,
            'persistence': 0.267, 'privilege_escalation': 0.333,
            'defense_evasion': 0.4, 'credential_access': 0.467,
            'discovery': 0.533, 'lateral_movement': 0.6,
            'collection': 0.667, 'command_and_control': 0.733,
            'exfiltration': 0.8, 'impact': 0.867
        }
        
        tactic = alert.get('enrichments', {}).get('mitre', {}).get('dominant_tactic', 'unknown')
        return tactic_encoding.get(tactic, 1.0)
    
    # === User/Asset Context ===
    
    def _user_is_known_good(self, alert: Dict) -> float:
        """User is whitelisted/trusted (1.0 or 0.0)"""
        if self.db is None:
            return 0.0
        
        username = alert.get('actor', {}).get('user', {}).get('name', '')
        if not username:
            return 0.0
        
        # Check whitelist
        whitelist = self.db.config.find_one({'_id': 'trusted_users'})
        if whitelist and username in whitelist.get('users', []):
            return 1.0
        
        return 0.0
    
    def _user_is_service_account(self, alert: Dict) -> float:
        """User is service account (automated activity)"""
        user_type_id = alert.get('actor', {}).get('user', {}).get('type_id', 1)
        return 1.0 if user_type_id == 3 else 0.0  # 3 = service account
    
    def _asset_is_scanner(self, alert: Dict) -> float:
        """Source/dest is known scanner (1.0 or 0.0)"""
        src_ip = alert.get('src_endpoint', {}).get('ip', '')
        hostname = alert.get('dst_endpoint', {}).get('hostname', '').lower()
        
        # Check if scanner keyword in hostname
        if any(scanner in hostname for scanner in self.SCANNER_INDICATORS):
            return 1.0
        
        # Check scanner IP list
        if self.db is None:
            return 0.0
        
        scanner_ips = self.db.config.find_one({'_id': 'scanner_ips'})
        if scanner_ips and src_ip in scanner_ips.get('ips', []):
            return 1.0
        
        return 0.0
    
    def _asset_is_dev_env(self, alert: Dict) -> float:
        """Asset is in dev/test environment (1.0 or 0.0)"""
        hostname = alert.get('dst_endpoint', {}).get('hostname', '').lower()
        
        dev_keywords = ['dev', 'test', 'staging', 'sandbox', 'demo', 'uat', 'qa']
        return 1.0 if any(kw in hostname for kw in dev_keywords) else 0.0
    
    def _source_is_internal(self, alert: Dict) -> float:
        """Source IP is internal RFC1918 (1.0 or 0.0)"""
        src_ip = alert.get('src_endpoint', {}).get('ip', '')
        
        if not src_ip:
            return 0.0
        
        # Check RFC1918 private ranges
        if src_ip.startswith('10.') or src_ip.startswith('192.168.') or src_ip.startswith('172.'):
            return 1.0
        
        return 0.0
    
    def _get_user_privilege_level(self, alert: Dict) -> float:
        """User privilege (0=normal, 0.5=admin, 1.0=system)"""
        user_type_id = alert.get('actor', {}).get('user', {}).get('type_id', 1)
        mapping = {1: 0.0, 2: 0.5, 3: 1.0}  # user, admin, system
        return mapping.get(user_type_id, 0.0)
    
    # === Temporal Patterns ===
    
    def _is_business_hours(self, alert: Dict) -> float:
        """Alert during business hours 9-5 Mon-Fri (1.0 or 0.0)"""
        alert_time = alert.get('time')
        if not alert_time:
            return 0.0
        
        dt = datetime.fromtimestamp(alert_time / 1000)
        
        # Monday=0, Friday=4
        if dt.weekday() <= 4 and 9 <= dt.hour < 17:
            return 1.0
        
        return 0.0
    
    def _is_weekend(self, alert: Dict) -> float:
        """Alert on weekend (1.0 or 0.0)"""
        alert_time = alert.get('time')
        if not alert_time:
            return 0.0
        
        dt = datetime.fromtimestamp(alert_time / 1000)
        return 1.0 if dt.weekday() >= 5 else 0.0
    
    def _get_time_of_day_entropy(self, alert: Dict) -> float:
        """Entropy of alert timing (0=very regular, 1=random)"""
        if self.db is None:
            return 0.5  # Unknown
        
        rule_id = alert.get('unmapped', {}).get('wazuh_rule_id')
        if not rule_id:
            return 0.5
        
        # Get last 20 alerts from this rule
        recent = list(self.db.alerts.find({
            'unmapped.wazuh_rule_id': rule_id
        }).sort('time', -1).limit(20))
        
        if len(recent) < 3:
            return 0.5  # Insufficient data
        
        # Extract hours of day
        hours = [datetime.fromtimestamp(a['time'] / 1000).hour for a in recent]
        
        # Calculate entropy
        hour_counts = Counter(hours)
        probabilities = [count / len(hours) for count in hour_counts.values()]
        entropy = -sum(p * np.log2(p) if p > 0 else 0 for p in probabilities)
        
        # Normalize to 0-1 (max entropy for 24 hours = 4.58)
        return min(entropy / 4.58, 1.0)
    
    def _is_repeated_pattern(self, alert: Dict) -> float:
        """Same alert pattern seen before (1.0 or 0.0)"""
        if self.db is None:
            return 0.0
        
        fingerprint = self._create_fingerprint(alert)
        
        # Check for similar alerts in last 7 days
        cutoff = datetime.now() - timedelta(days=7)
        cutoff_ms = int(cutoff.timestamp() * 1000)
        
        similar = self.db.alert_fingerprints.find_one({
            'fingerprint': fingerprint,
            'last_seen': {'$gte': cutoff_ms}
        })
        
        return 1.0 if similar else 0.0
    
    def _get_time_since_last_similar(self, alert: Dict) -> float:
        """Minutes since last similar alert (capped at 1440 = 1 day)"""
        if self.db is None:
            return 1440.0  # Max value
        
        fingerprint = self._create_fingerprint(alert)
        
        last = self.db.alert_fingerprints.find_one({'fingerprint': fingerprint})
        
        if not last:
            return 1440.0
        
        current_time = alert.get('time', datetime.now().timestamp() * 1000)
        last_time = last.get('last_seen', 0)
        
        minutes = (current_time - last_time) / (1000 * 60)
        
        return min(minutes, 1440.0)
    
    # === Historical Feedback ===
    
    def _get_similar_fp_count(self, alert: Dict, days: int = 7) -> float:
        """Count of similar false positives in last N days (capped at 50)"""
        if self.db is None:
            return 0.0
        
        fingerprint = self._create_fingerprint(alert)
        cutoff = datetime.now() - timedelta(days=days)
        cutoff_ms = int(cutoff.timestamp() * 1000)
        
        count = self.db.alerts.count_documents({
            'fingerprint': fingerprint,
            'time': {'$gte': cutoff_ms},
            'analyst_verdict': 'false_positive'
        })
        
        return min(count, 50.0)
    
    def _get_similar_tp_count(self, alert: Dict, days: int = 7) -> float:
        """Count of similar true positives in last N days (capped at 50)"""
        if self.db is None:
            return 0.0
        
        fingerprint = self._create_fingerprint(alert)
        cutoff = datetime.now() - timedelta(days=days)
        cutoff_ms = int(cutoff.timestamp() * 1000)
        
        count = self.db.alerts.count_documents({
            'fingerprint': fingerprint,
            'time': {'$gte': cutoff_ms},
            'analyst_verdict': 'true_positive'
        })
        
        return min(count, 50.0)
    
    def _get_fp_rate_for_rule(self, alert: Dict) -> float:
        """Historical FP rate for this rule (0-1)"""
        if self.db is None:
            return 0.0
        
        rule_id = alert.get('unmapped', {}).get('wazuh_rule_id')
        if not rule_id:
            return 0.0
        
        noisy_rule = self.db.noisy_rules.find_one({'rule_id': rule_id})
        
        if noisy_rule:
            return noisy_rule.get('fp_rate', 0.0)
        
        return 0.0
    
    def _get_analyst_dismissed_count(self, alert: Dict) -> float:
        """Times similar alerts quickly dismissed (capped at 20)"""
        if self.db is None:
            return 0.0
        
        fingerprint = self._create_fingerprint(alert)
        
        count = self.db.alerts.count_documents({
            'fingerprint': fingerprint,
            'investigation_time_seconds': {'$lt': 30},  # Dismissed in <30s
            'analyst_verdict': 'false_positive'
        })
        
        return min(count, 20.0)
    
    def _get_avg_investigation_time(self, alert: Dict) -> float:
        """Average investigation time for similar alerts (seconds, capped at 600)"""
        if self.db is None:
            return 300.0  # Default 5 minutes
        
        fingerprint = self._create_fingerprint(alert)
        
        pipeline = [
            {'$match': {
                'fingerprint': fingerprint,
                'investigation_time_seconds': {'$exists': True}
            }},
            {'$group': {
                '_id': None,
                'avg_time': {'$avg': '$investigation_time_seconds'}
            }}
        ]
        
        result = list(self.db.alerts.aggregate(pipeline))
        
        if result:
            return min(result[0]['avg_time'], 600.0)
        
        return 300.0
    
    def _get_escalation_rate(self, alert: Dict) -> float:
        """% of similar alerts escalated to incidents (0-1)"""
        if self.db is None:
            return 0.0
        
        fingerprint = self._create_fingerprint(alert)
        
        total = self.db.alerts.count_documents({'fingerprint': fingerprint})
        
        if total == 0:
            return 0.0
        
        escalated = self.db.alerts.count_documents({
            'fingerprint': fingerprint,
            'incident_id': {'$exists': True}
        })
        
        return escalated / total
    
    # === Helper Methods ===
    
    def _create_fingerprint(self, alert: Dict) -> str:
        """Create fingerprint for similarity matching"""
        rule_id = alert.get('unmapped', {}).get('wazuh_rule_id', '')
        title = alert.get('finding', {}).get('title', '').lower()
        src_ip = alert.get('src_endpoint', {}).get('ip', '')
        dst_host = alert.get('dst_endpoint', {}).get('hostname', '')
        user = alert.get('actor', {}).get('user', {}).get('name', '')
        severity = alert.get('severity_id', 0)
        
        # Normalize title (remove variables)
        title_norm = re.sub(r'\d+\.\d+\.\d+\.\d+', 'IP', title)
        title_norm = re.sub(r'\d+', 'NUM', title_norm)
        
        composite = f"{rule_id}|{title_norm}|{src_ip}|{dst_host}|{user}|{severity}"
        
        return hashlib.md5(composite.encode()).hexdigest()


# Global instance
fp_feature_extractor = FPFeatureExtractor()
