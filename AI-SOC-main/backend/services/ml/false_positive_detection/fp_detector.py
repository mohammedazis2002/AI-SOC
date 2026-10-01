"""
False Positive Detector

Hybrid approach: Rule-based + ML (when trained)
Works Day 1 with rules, improves with data
"""

import logging
import joblib
import os
from typing import Dict, Any, List, Tuple
from pathlib import Path
from datetime import datetime, timedelta
from pymongo import MongoClient

from backend.services.ml.false_positive_detection.fp_feature_extractor import FPFeatureExtractor

logger = logging.getLogger(__name__)


class FalsePositiveDetector:
    """
   False positive detector using hybrid rule-based + ML approach
    
    Starts with rule-based detection (works Day 1)
    Upgrades to ML when trained model available
    """
    
    def __init__(self, db_client=None, model_path='models/fp_detector.pkl'):
        """
        Args:
            db_client: MongoDB client
            model_path: Path to trained ML model (optional)
        """
        # Motor/PyMongo database objects do not implement truthiness.
        self.db = db_client if db_client is not None else MongoClient()['soar_db']
        self.feature_extractor = FPFeatureExtractor(self.db)
        
        # Try to load ML model
        self.ml_model = None
        self.model_metadata = None
        
        if os.path.exists(model_path):
            try:
                model_data = joblib.load(model_path)
                self.ml_model = model_data['model']
                self.model_metadata = model_data.get('metadata', {})
                logger.info(f"Loaded ML model: {self.model_metadata.get('accuracy', 'N/A')} accuracy")
            except Exception as e:
                logger.warning(f"Failed to load ML model: {e}")
    
    def detect(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect if alert is a false positive
        
        Args:
            alert: OCSF ULF alert
            
        Returns:
            {
                'fp_score': float (0-1),
                'confidence': float (0-1),
                'method': str ('rules', 'ml', 'hybrid'),
                'reasons': list,
                'recommendation': dict,
                'similar_fps': list
            }
        """
        # Extract features
        features = self.feature_extractor.extract(alert)
        
        # Rule-based detection (always run)
        rule_score, rule_reasons = self._rule_based_detect(alert, features)
        
        # ML detection (if model available)
        if self.ml_model:
            ml_score, ml_confidence = self._ml_detect(features)
            
            # Hybrid: combine both
            final_score = (ml_score * 0.7) + (rule_score * 0.3)
            method = 'hybrid'
            confidence = ml_confidence
        else:
            # Rules only
            final_score = rule_score
            method = 'rules_only'
            # High confidence when we're certain (very high OR very low score)
            # Low confidence when uncertain (middle range)
            is_certain = (rule_score >= 0.7) or (rule_score <= 0.3)
            confidence = 0.75 if is_certain else 0.5
        
        # Find similar past false positives
        similar_fps = self._find_similar_fps(alert)
        
        # Generate recommendation
        recommendation = self._generate_recommendation(final_score, confidence, alert)
        
        return {
            'fp_score': float(final_score),
            'confidence': float(confidence),
            'method': method,
            'reasons': rule_reasons,
            'recommendation': recommendation,
            'similar_fps': similar_fps[:5],  # Top 5
            'analyzed_at': datetime.now().isoformat()
        }
    
    def _rule_based_detect(self, alert: Dict, features: Any) -> Tuple[float, List[str]]:
        """
        Improved rule-based FP detection
        
        Uses grouped features + tiered voting to eliminate bias
        
        Returns:
            (fp_score, reasons)
        """
        reasons = []
        
        # === STEP 1: Extract Grouped Signals (eliminates double-counting) ===
        
        # Group 1: Scanner Indicators (take max to avoid correlation)
        scanner_signals = []
        if features[10] == 1.0:  # asset_is_scanner
            scanner_signals.append(0.9)
            reasons.append("Traffic from known vulnerability scanner")
        if 'scanner' in alert.get('src_endpoint', {}).get('hostname', '').lower():
            scanner_signals.append(0.85)
        if 'scan' in alert.get('finding', {}).get('title', '').lower():
            scanner_signals.append(0.75)
            if "Traffic from known vulnerability scanner" not in reasons:
                reasons.append("Alert title contains 'scan' keyword")
        
        scanner_score = max(scanner_signals) if scanner_signals else 0.0
        
        # Group 2: Environment Indicators
        env_signals = []
        if features[11] == 1.0:  # asset_is_dev_env
            env_signals.append(0.85)
            reasons.append("Alert from development/test environment")
        if features[3] >= 0.5:  # has_fp_keywords (test, dev, demo, etc.)
            env_signals.append(0.70)
            if "Alert from development/test environment" not in reasons:
                reasons.append("Contains FP keywords (test, dev, demo, etc.)")
        
        env_score = max(env_signals) if env_signals else 0.0
        
        # Group 3: Historical Patterns
        history_signals = []
        if features[6] == 1.0:  # is_noisy_rule
            noisy_rule = self._get_noisy_rule_details(alert)
            if noisy_rule:
                history_score = noisy_rule['fp_rate'] * 0.9
                history_signals.append(history_score)
                reasons.append(f"Rule has {noisy_rule['fp_rate']*100:.0f}% historical FP rate")
        
        if features[20] >= 5:  # similar_fp_count
            similarity_score = min(features[20] / 15, 0.8)  # Cap at 0.8
            history_signals.append(similarity_score)
            reasons.append(f"{int(features[20])} similar alerts recently marked as FP")
        
        if features[23] >= 3:  # analyst_dismissed_count
            dismissal_score = min(features[23] / 10, 0.7)  # Cap at 0.7
            history_signals.append(dismissal_score)
            reasons.append(f"Analysts quickly dismissed {int(features[23])} similar alerts")
        
        history_score = max(history_signals) if history_signals else 0.0
        
        # Group 4: Behavioral Indicators
        behavior_signals = []
        if features[9] == 1.0 and features[12] == 1.0:  # service account + internal
            behavior_signals.append(0.60)
            reasons.append("Service account activity from internal network")
        
        if features[16] < 0.15 and features[18] == 1.0:  # very low entropy + repeated
            behavior_signals.append(0.75)
            reasons.append("Very regular pattern (likely scheduled task)")
        elif features[16] < 0.3:  # low entropy
            behavior_signals.append(0.50)
        
        if features[14] == 1.0 and features[12] == 1.0 and features[0] < 0.5:
            # Business hours + internal + low severity
            behavior_signals.append(0.40)
            if "Service account" not in str(reasons):
                reasons.append("Low severity internal activity during business hours")
        
        behavior_score = max(behavior_signals) if behavior_signals else 0.0
        
        # Group 5: Threat Intelligence (inverse - low TI = higher FP likelihood)
        ti_score = features[4]  # threat_intel_score
        freq_score = features[2]  # alert_frequency_score
        
        if ti_score < 0.2 and freq_score >= 0.6:
            ti_fp_score = 0.65
            reasons.append("Low threat intelligence with high alert frequency")
        elif ti_score < 0.3:
            ti_fp_score = 0.40
        else:
            ti_fp_score = 0.0
        
        # === STEP 2: Tiered Decision Logic ===
        
        # Tier 1: VERY STRONG signals (any one is enough)
        if scanner_score >= 0.85 or history_score >= 0.80:
            fp_score = max(scanner_score, history_score)
            if fp_score >= 0.90:
                return 0.95, reasons  # Very high confidence
            else:
                return fp_score, reasons
        
        # Tier 2: STRONG signals (need 2+)
        strong_signals = [
            (scanner_score, 1.2),    # Scanner is strongest
            (env_score, 1.0),        # Environment
            (history_score, 1.1)     # Historical FP rate
        ]
        
        active_strong = [(score, weight) for score, weight in strong_signals if score >= 0.65]
        
        if len(active_strong) >= 2:
            # Weighted average of strong signals
            total_weight = sum(w for _, w in active_strong)
            fp_score = sum(s * w for s, w in active_strong) / total_weight
            return min(fp_score, 0.95), reasons
        
        # Tier 3: MODERATE signals (need 2-3)
        moderate_signals = [
            env_score,
            behavior_score,
            ti_fp_score,
            scanner_score,
            history_score
        ]
        
        active_moderate = [s for s in moderate_signals if 0.4 <= s < 0.65]
        
        if len(active_moderate) >= 2:
            fp_score = sum(active_moderate) / (len(active_moderate) + 1)  # Conservative average
            return min(fp_score, 0.75), reasons
        
        # Tier 4: Single strong or multiple weak signals
        all_scores = [scanner_score, env_score, history_score, behavior_score, ti_fp_score]
        max_score = max(all_scores)
        
        if max_score >= 0.60:
            return min(max_score, 0.70), reasons
        
        active_weak = [s for s in all_scores if 0.2 <= s < 0.4]
        if len(active_weak) >= 3:
            return 0.55, reasons
        
        # Default: Likely true positive
        if not reasons:
            reasons.append("No significant FP indicators found - appears legitimate")
        
        return 0.0, reasons
    
    def _ml_detect(self, features: Any) -> Tuple[float, float]:
        """
        ML-based FP detection
        
        Returns:
            (fp_probability, confidence)
        """
        try:
            # Predict probability
            proba = self.ml_model.predict_proba([features])[0]
            fp_probability = proba[1]  # Probability of FP class
            
            # Confidence = how far from 0.5 (uncertain)
            confidence = abs(fp_probability - 0.5) * 2
            
            return fp_probability, confidence
        except Exception as e:
            logger.error(f"ML prediction failed: {e}")
            return 0.5, 0.0
    
    def _find_similar_fps(self, alert: Dict) -> List[Dict]:
        """Find alerts similar to known false positives"""
        fingerprint = self.feature_extractor._create_fingerprint(alert)
        
        # Query for similar FPs in last 30 days
        cutoff = datetime.now() - timedelta(days=30)
        cutoff_ms = int(cutoff.timestamp() * 1000)
        
        similar = list(self.db.alerts.find({
            'fingerprint': fingerprint,
            'time': {'$gte': cutoff_ms},
            'analyst_verdict': 'false_positive'
        }).limit(10))
        
        return [
            {
                'alert_id': s.get('alert_id'),
                'time': s.get('time'),
                'analyst': s.get('analyst', 'unknown'),
                'reason': s.get('review_reason', 'N/A')
            }
            for s in similar
        ]
    
    def _get_noisy_rule_details(self, alert: Dict) -> Dict:
        """Get noisy rule details"""
        rule_id = alert.get('unmapped', {}).get('wazuh_rule_id')
        if not rule_id:
            return None
        
        return self.db.noisy_rules.find_one({'rule_id': rule_id})
    
    def _generate_recommendation(self, fp_score: float, confidence: float, alert: Dict) -> Dict:
        """
        Generate auto-triage recommendation
        
        Conservative approach to minimize false negatives
        """
        severity = alert.get('severity_id', 2)
        mitre_tactic = alert.get('enrichments', {}).get('mitre', {}).get('dominant_tactic', '')
        threat_intel_score = alert.get('enrichments', {}).get('threat_intel', {}).get('score', 0)
        
        # Safety nets: Never auto-close these
        high_risk_tactics = [
            'initial_access',      # Entry point attacks
            'execution',           # Code/command execution  
            'privilege_escalation', # Elevation attacks
            'defense_evasion',     # Hiding/obfuscation
            'credential_access',   # Credential theft
            'lateral_movement',    # Network propagation
            'collection',          # Data gathering
            'command_and_control', # C2 communication
            'exfiltration',        # Data theft
            'impact'               # Destructive actions
        ]
        
        # Safety Net 1: High or Critical severity
        if severity >= 3:  # High (3) or Critical (4)
            return {
                'action': 'investigate',
                'priority': 'high',
                'reason': f'High/Critical severity (level {severity}) - manual review required'
            }
        
        # Safety Net 2: High-risk MITRE tactic
        if mitre_tactic in high_risk_tactics:
            return {
                'action': 'investigate',
                'priority': 'high',
                'reason': f'High-risk tactic ({mitre_tactic}) - manual review required'
            }
        
        # Safety Net 3: High threat intelligence score
        if threat_intel_score >= 0.8:
            return {
                'action': 'investigate',
                'priority': 'high',
                'reason': f'High threat intelligence score ({threat_intel_score:.0%}) - manual review required'
            }
        
        # Tiered thresholds
        if fp_score >= 0.90 and confidence >= 0.95:
            return {
                'action': 'auto_close',
                'priority': None,
                'reason': 'Very high confidence false positive',
                'requires_review': False
            }
        
        elif fp_score >= 0.80 and confidence >= 0.85:
            return {
                'action': 'suppress',
                'priority': 'low',
                'reason': 'Likely false positive - suppressed from main queue',
                'requires_review': True  # Analyst can review if needed
            }
        
        elif fp_score >= 0.70:
            return {
                'action': 'deprioritize',
                'priority': 'low',
                'reason': 'Possible false positive - moved to low priority',
                'requires_review': True
            }
        
        elif fp_score >= 0.50:
            return {
                'action': 'investigate',
                'priority': 'medium',
                'reason': 'Uncertain - manual review recommended',
                'requires_review': True
            }
        
        else:
            return {
                'action': 'investigate',
                'priority': 'high',
                'reason': 'Likely true positive',
                'requires_review': True
            }
    
    def batch_detect(self, alerts: List[Dict]) -> List[Dict]:
        """
        Detect FPs in batch
        
        Args:
            alerts: List of alerts
            
        Returns:
            List of detection results
        """
        return [self.detect(alert) for alert in alerts]
    
    def update_noisy_rules(self, min_alerts=50, fp_threshold=0.6):
        """
        Update noisy rules list from historical data
        
        Args:
            min_alerts: Minimum alert count to consider
            fp_threshold: FP rate threshold (0.6 = 60%)
        """
        logger.info("Updating noisy rules list...")
        
        pipeline = [
            {'$match': {'analyst_verdict': {'$exists': True}}},
            {'$group': {
                '_id': '$unmapped.wazuh_rule_id',
                'rule_name': {'$first': '$finding.title'},
                'total': {'$sum': 1},
                'fp_count': {'$sum': {
                    '$cond': [{'$eq': ['$analyst_verdict', 'false_positive']}, 1, 0]
                }}
            }},
            {'$project': {
                'rule_id': '$_id',
                'rule_name': 1,
                'total': 1,
                'fp_count': 1,
                'fp_rate': {'$divide': ['$fp_count', '$total']}
            }},
            {'$match': {
                'total': {'$gte': min_alerts},
                'fp_rate': {'$gte': fp_threshold}
            }},
            {'$sort': {'fp_rate': -1}}
        ]
        
        noisy_rules = list(self.db.alerts.aggregate(pipeline))
        
        # Update collection
        self.db.noisy_rules.delete_many({})  # Clear old
        
        for rule in noisy_rules:
            rule['last_updated'] = datetime.now()
            self.db.noisy_rules.insert_one(rule)
        
        logger.info(f"Updated noisy rules: {len(noisy_rules)} rules identified")
        
        return noisy_rules


# Global instance
fp_detector = FalsePositiveDetector()
