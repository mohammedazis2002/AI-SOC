"""
Feature Extractor for Root Cause Analysis
Converts ULF alerts + context into 30-dimensional feature vectors
"""

import logging
import numpy as np
from typing import Dict, Any, List
from datetime import datetime
from collections import Counter

logger = logging.getLogger(__name__)


class RootCauseFeatureExtractor:
    """
    Extract 30 features from ULF alerts for root cause prediction
    
    Feature Categories:
    - Alert Context (10 features)
    - User/Asset (8 features)
    - Attack Patterns (7 features)
    - Historical Context (5 features)
    """
    
    # MITRE tactic encoding
    TACTIC_ENCODING = {
        'reconnaissance': 0, 'resource_development': 1, 'initial_access': 2,
        'execution': 3, 'persistence': 4, 'privilege_escalation': 5,
        'defense_evasion': 6, 'credential_access': 7, 'discovery': 8,
        'lateral_movement': 9, 'collection': 10, 'command_and_control': 11,
        'exfiltration': 12, 'impact': 13, 'unknown': 14
    }
    
    # Feature names for reference
    FEATURE_NAMES = [
        # Alert Context (10)
        'severity_id', 'mitre_tactic_encoded', 'technique_count',
        'alert_freq_1h', 'alert_freq_24h', 'is_after_hours',
        'is_weekend', 'source_country_risk', 'asset_criticality', 'detection_time_min',
        
        # User/Asset (8)
        'user_has_mfa', 'user_privilege_level', 'account_age_days',
        'patch_age_days', 'has_edr', 'segmentation_level',
        'failed_login_count_24h', 'privilege_changes_7d',
        
        # Attack Patterns (7)
        'is_brute_force', 'is_lateral_movement', 'is_exfiltration',
        'uses_known_exploit', 'uses_lolbins', 'credential_reuse', 'anomaly_score',
        
        # Historical Context (5)
        'similar_attacks_30d', 'victim_targeted_before', 'attacker_seen_before',
        'avg_remediation_time_days', 'fp_rate'
    ]
    
    def __init__(self, db_client=None):
        """
        Args:
            db_client: MongoDB client for historical queries
        """
        self.db = db_client
    
    def extract(self, alert: Dict[str, Any], context: Dict[str, Any] = None) -> np.ndarray:
        """
        Extract all 30 features from alert
        
        Args:
            alert: ULF alert dictionary
            context: Additional context (historical data, asset info, etc.)
            
        Returns:
            Feature vector (30,)
        """
        if context is None:
            context = {}
        
        features = []
        
        # === Alert Context (10 features) ===
        features.append(self._get_severity(alert))
        features.append(self._get_mitre_tactic_encoded(alert))
        features.append(self._get_technique_count(alert))
        features.append(self._get_alert_frequency(alert, hours=1, context=context))
        features.append(self._get_alert_frequency(alert, hours=24, context=context))
        features.append(self._is_after_hours(alert))
        features.append(self._is_weekend(alert))
        features.append(self._get_source_risk(alert, context))
        features.append(self._get_asset_criticality(alert, context))
        features.append(self._get_detection_time(alert, context))
        
        # === User/Asset (8 features) ===
        features.append(self._user_has_mfa(alert, context))
        features.append(self._get_user_privilege(alert, context))
        features.append(self._get_account_age(alert, context))
        features.append(self._get_patch_age(alert, context))
        features.append(self._has_edr(alert, context))
        features.append(self._get_segmentation_level(alert, context))
        features.append(self._get_failed_login_count(alert, context))
        features.append(self._get_privilege_changes(alert, context))
        
        # === Attack Patterns (7 features) ===
        features.append(self._is_brute_force(alert))
        features.append(self._is_lateral_movement(alert))
        features.append(self._is_exfiltration(alert))
        features.append(self._uses_known_exploit(alert))
        features.append(self._uses_lolbins(alert))
        features.append(self._credential_reuse_detected(alert, context))
        features.append(self._get_anomaly_score(alert, context))
        
        # === Historical Context (5 features) ===
        features.append(self._get_similar_attacks(alert, context))
        features.append(self._victim_targeted_before(alert, context))
        features.append(self._attacker_seen_before(alert, context))
        features.append(self._get_avg_remediation_time(alert, context))
        features.append(self._get_fp_rate(alert, context))
        
        return np.array(features, dtype=np.float32)
    
    # === Alert Context Extractors ===
    
    def _get_severity(self, alert: Dict) -> float:
        """Severity ID (0-5)"""
        return float(alert.get('severity_id', 2))
    
    def _get_mitre_tactic_encoded(self, alert: Dict) -> float:
        """Encoded MITRE tactic (0-14)"""
        tactic = alert.get('mitre_enrichment', {}).get('dominant_tactic', 'unknown')
        return float(self.TACTIC_ENCODING.get(tactic, 14))
    
    def _get_technique_count(self, alert: Dict) -> float:
        """Number of MITRE techniques"""
        techniques = alert.get('finding', {}).get('types', [])
        return float(len(techniques))
    
    def _get_alert_frequency(self, alert: Dict, hours: int, context: Dict) -> float:
        """Count of alerts in the last N hours"""
        recent_alerts = context.get('recent_alerts', [])
        if not recent_alerts:
            return 0.0
        
        current_time = alert.get('time', datetime.now().timestamp() * 1000)
        if not isinstance(current_time, (int, float)):
            current_time = datetime.now().timestamp() * 1000
        
        cutoff = current_time - (hours * 3600 * 1000)  # milliseconds
        
        count = 0
        for past_alert in recent_alerts:
            alert_time = past_alert.get('time', 0)
            if alert_time >= cutoff:
                count += 1
        
        return float(count)
    
    def _is_after_hours(self, alert: Dict) -> float:
        """Alert occurred outside business hours (1.0 or 0.0)"""
        alert_time = alert.get('time')
        if not alert_time:
            return 0.0
        
        if isinstance(alert_time, int):
            alert_time = datetime.fromtimestamp(alert_time / 1000)
        elif isinstance(alert_time, str):
            alert_time = datetime.fromisoformat(alert_time.replace('Z', '+00:00'))
        
        # After hours = before 6 AM or after 8 PM
        if alert_time.hour < 6 or alert_time.hour >= 20:
            return 1.0
        return 0.0
    
    def _is_weekend(self, alert: Dict) -> float:
        """Alert occurred on weekend (1.0 or 0.0)"""
        alert_time = alert.get('time')
        if not alert_time:
            return 0.0
        
        if isinstance(alert_time, int):
            alert_time = datetime.fromtimestamp(alert_time / 1000)
        elif isinstance(alert_time, str):
            alert_time = datetime.fromisoformat(alert_time.replace('Z', '+00:00'))
        
        # Saturday=5, Sunday=6
        if alert_time.weekday() >= 5:
            return 1.0
        return 0.0
    
    def _get_source_risk(self, alert: Dict, context: Dict) -> float:
        """Source country risk score (0-1)"""
        # Placeholder - would use GeoIP lookup
        return context.get('source_risk_score', 0.5)
    
    def _get_asset_criticality(self, alert: Dict, context: Dict) -> float:
        """Destination asset criticality (0-1)"""
        # Get from asset_profile if available
        asset_profile = context.get('asset_profile', {})
        if asset_profile:
            criticality = asset_profile.get('criticality', 3)  # 1-5 scale
            return criticality / 5.0  # Normalize to 0-1
        return context.get('asset_criticality', 0.5)
    
    def _get_detection_time(self, alert: Dict, context: Dict) -> float:
        """Time to detection in minutes"""
        return context.get('detection_time_minutes', 0.0)
    
    # === User/Asset Extractors ===
    
    def _user_has_mfa(self, alert: Dict, context: Dict) -> float:
        """User has MFA enabled (1.0 or 0.0)"""
        return 1.0 if context.get('user_mfa_enabled', False) else 0.0
    
    def _get_user_privilege(self, alert: Dict, context: Dict) -> float:
        """User privilege level (0=normal, 1=admin, 2=system)"""
        # Get from user_profile if available
        user_profile = context.get('user_profile', {})
        if user_profile and user_profile.get('is_privileged'):
            return 1.0
        
        # Fallback to alert data
        user_type_id = alert.get('actor', {}).get('user', {}).get('type_id', 1)
        return float(user_type_id - 1)  # 1=user=0, 2=admin=1, 3=system=2
    
    def _get_account_age(self, alert: Dict, context: Dict) -> float:
        """Account age in days"""
        user_profile = context.get('user_profile', {})
        if user_profile:
            return float(user_profile.get('account_age_days', 30))
        return context.get('account_age_days', 30.0)
    
    def _get_patch_age(self, alert: Dict, context: Dict) -> float:
        """Days since last patch"""
        return context.get('patch_age_days', 30.0)
    
    def _has_edr(self, alert: Dict, context: Dict) -> float:
        """EDR installed (1.0 or 0.0)"""
        return 1.0 if context.get('has_edr', False) else 0.0
    
    def _get_segmentation_level(self, alert: Dict, context: Dict) -> float:
        """Network segmentation level (0=flat, 1=basic, 2=strict)"""
        seg_map = {'flat': 0, 'none': 0, 'basic': 1, 'strict': 2, 'zero_trust': 2}
        seg_level = context.get('segmentation', 'flat').lower()
        return float(seg_map.get(seg_level, 0))
    
    def _get_failed_login_count(self, alert: Dict, context: Dict) -> float:
        """Failed login attempts in last 24h"""
        return context.get('failed_logins_24h', 0.0)
    
    def _get_privilege_changes(self, alert: Dict, context: Dict) -> float:
        """Privilege escalations in last 7 days"""
        return context.get('privilege_changes_7d', 0.0)
    
    # === Attack Pattern Extractors ===
    
    def _is_brute_force(self, alert: Dict) -> float:
        """Is brute force attack (1.0 or 0.0)"""
        techniques = alert.get('finding', {}).get('types', [])
        description = str(alert.get('finding', {}).get('desc', '')).lower()
        
        if 'T1110' in techniques or any(word in description for word in ['brute', 'failed password']):
            return 1.0
        return 0.0
    
    def _is_lateral_movement(self, alert: Dict) -> float:
        """Is lateral movement (1.0 or 0.0)"""
        tactic = alert.get('mitre_enrichment', {}).get('dominant_tactic', '')
        if tactic == 'lateral_movement':
            return 1.0
        return 0.0
    
    def _is_exfiltration(self, alert: Dict) -> float:
        """Is data exfiltration (1.0 or 0.0)"""
        tactic = alert.get('mitre_enrichment', {}).get('dominant_tactic', '')
        if tactic == 'exfiltration':
            return 1.0
        return 0.0
    
    def _uses_known_exploit(self, alert: Dict) -> float:
        """Uses known CVE (1.0 or 0.0)"""
        description = str(alert.get('finding', {}).get('desc', ''))
        raw_data = str(alert.get('raw_data', ''))
        
        if 'CVE-' in description or 'CVE-' in raw_data:
            return 1.0
        return 0.0
    
    def _uses_lolbins(self, alert: Dict) -> float:
        """Uses living-off-the-land binaries (1.0 or 0.0)"""
        lolbins = ['powershell', 'cmd.exe', 'wmi', 'psexec', 'rundll32', 'regsvr32', 'mshta']
        description = str(alert.get('finding', {}).get('desc', '')).lower()
        process_name = str(alert.get('process', {}).get('name', '')).lower()
        
        if any(lol in description or lol in process_name for lol in lolbins):
            return 1.0
        return 0.0
    
    def _credential_reuse_detected(self, alert: Dict, context: Dict) -> float:
        """Credential reuse detected (1.0 or 0.0)"""
        return 1.0 if context.get('credential_reuse', False) else 0.0
    
    def _get_anomaly_score(self, alert: Dict, context: Dict) -> float:
        """Anomaly score from Model 1 (0-1)"""
        return context.get('anomaly_score', 0.5)
    
    # === Historical Context Extractors ===
    
    def _get_similar_attacks(self, alert: Dict, context: Dict) -> float:
        """Similar attacks in last 30 days"""
        return context.get('similar_attacks_30d', 0.0)
    
    def _victim_targeted_before(self, alert: Dict, context: Dict) -> float:
        """Victim targeted before (1.0 or 0.0)"""
        return 1.0 if context.get('victim_history', False) else 0.0
    
    def _attacker_seen_before(self, alert: Dict, context: Dict) -> float:
        """Attacker seen before (1.0 or 0.0)"""
        return 1.0 if context.get('attacker_history', False) else 0.0
    
    def _get_avg_remediation_time(self, alert: Dict, context: Dict) -> float:
        """Average remediation time for this alert type (days)"""
        return context.get('avg_fix_time_days', 7.0)
    
    def _get_fp_rate(self, alert: Dict, context: Dict) -> float:
        """False positive rate for alert type (0-1)"""
        return context.get('fp_rate', 0.1)
    
    def extract_batch(self, alerts: List[Dict], contexts: List[Dict] = None) -> np.ndarray:
        """
        Extract features for multiple alerts
        
        Args:
            alerts: List of ULF alerts
            contexts: Optional list of contexts (one per alert)
            
        Returns:
            Feature matrix (n_alerts, 30)
        """
        if contexts is None:
            contexts = [{}] * len(alerts)
        
        features = []
        for alert, context in zip(alerts, contexts):
            features.append(self.extract(alert, context))
        
        return np.array(features)


# Module-level instance
feature_extractor = RootCauseFeatureExtractor()
