"""
Model 3: Root Cause Analyzer
Identifies WHY attacks succeeded using Multi-Label Random Forest

Categories: 14 root causes
Approach: Semi-supervised labeling + temporal priority analysis
Output: Root causes with confidence, origin cause, remediation
"""

from sklearn.ensemble import RandomForestClassifier
from sklearn.multioutput import MultiOutputClassifier
import numpy as np
import pandas as pd
import pickle
import logging
from typing import Dict, List, Any, Tuple
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)


class RootCauseAnalyzer:
    """
    Multi-label Random Forest classifier for root cause identification
    
    Features:
    - 14 root cause categories
    - Semi-supervised labeling support
    - Temporal priority analysis
    - Origin cause identification via dependency graphs
    """
    
    # 14 Root Cause Categories
    CATEGORIES = [
        'weak_credentials',           # Weak/default/reused passwords
        'unpatched_vulnerability',    # Missing security patches (CVEs)
        'misconfiguration',           # Network/cloud/API misconfigurations
        'lack_of_mfa',                # No multi-factor authentication
        'insufficient_monitoring',    # Logging/detection gaps
        'social_engineering',         # Phishing, pretexting
        'insider_threat',             # Malicious/negligent insider
        'supply_chain',               # Third-party compromise
        'zero_day_exploit',           # Unknown vulnerability
        'inadequate_segmentation',    # Poor network isolation
        'excessive_privileges',       # Over-permissioned accounts
        'outdated_software',          # End-of-life software
        'defense_evasion',            # LOLBIN abuse, obfuscation
        'api_security_gap'            # Insecure APIs, broken auth
    ]
    
    # MITRE technique → likely root causes (for semi-supervised labeling)
    TECHNIQUE_HINTS = {
        'T1110': ['weak_credentials', 'lack_of_mfa'],  # Brute Force
        'T1078': ['weak_credentials', 'excessive_privileges'],  # Valid Accounts
        'T1190': ['unpatched_vulnerability', 'api_security_gap'],  # Exploit Public App
        'T1133': ['misconfiguration', 'lack_of_mfa'],  # External Remote Services
        'T1059': ['defense_evasion', 'inadequate_segmentation'],  # Command/Script
        'T1562': ['defense_evasion', 'insufficient_monitoring'],  # Impair Defenses
        'T1070': ['defense_evasion', 'insufficient_monitoring'],  # Indicator Removal
        'T1021': ['inadequate_segmentation', 'excessive_privileges'],  # Remote Services
        'T1071': ['api_security_gap', 'insufficient_monitoring'],  # Application Layer
        'T1204': ['social_engineering', 'insufficient_monitoring'],  # User Execution
        'T1588': ['supply_chain', 'insufficient_monitoring'],  # Obtain Capabilities
        'T1195': ['supply_chain', 'insufficient_monitoring'],  # Supply Chain Compromise
    }
    
    # Tactic ordering (for temporal priority)
    TACTIC_ORDER = {
        'reconnaissance': 1,
        'resource_development': 2,
        'initial_access': 3,
        'execution': 4,
        'persistence': 5,
        'privilege_escalation': 6,
        'defense_evasion': 7,
        'credential_access': 8,
        'discovery': 9,
        'lateral_movement': 10,
        'collection': 11,
        'command_and_control': 12,
        'exfiltration': 13,
        'impact': 14
    }
    
    def __init__(self):
        """Initialize multi-label classifier"""
        # One Random Forest per category (14 classifiers)
        base_rf = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced',  # Handle class imbalance
            random_state=42,
            n_jobs=-1  # Use all CPU cores
        )
        
        self.model = MultiOutputClassifier(base_rf, n_jobs=-1)
        self.trained = False
        
        # Feature names for interpretability
        self.feature_names = []
        
        # Statistics
        self.train_stats = {}
    
    def auto_suggest_labels(self, alert: Dict[str, Any]) -> Dict[str, float]:
        """
        Semi-supervised: Auto-suggest root cause labels based on patterns
        
        Analyst can then confirm/correct these suggestions
        
        Args:
            alert: ULF alert dictionary
            
        Returns:
            Suggested labels with confidence scores
        """
        suggestions = defaultdict(float)
        
        # Rule 1: MITRE technique hints
        techniques = alert.get('finding', {}).get('types', [])
        for tech in techniques:
            if tech in self.TECHNIQUE_HINTS:
                for cause in self.TECHNIQUE_HINTS[tech]:
                    suggestions[cause] = max(suggestions[cause], 0.75)
        
        # Rule 2: Brute force patterns
        finding_desc = str(alert.get('finding', {}).get('desc', '')).lower()
        if any(word in finding_desc for word in ['brute', 'failed password', 'multiple attempts']):
            suggestions['weak_credentials'] = 0.85
            
            # If no MFA detected
            if not alert.get('user_has_mfa', True):
                suggestions['lack_of_mfa'] = 0.80
        
        # Rule 3: CVE/Vulnerability
        if 'CVE-' in finding_desc or 'exploit' in finding_desc:
            suggestions['unpatched_vulnerability'] = 0.90
        
        # Rule 4: After-hours activity
        alert_time = alert.get('time')
        if isinstance(alert_time, int):
            alert_time = datetime.fromtimestamp(alert_time / 1000)
        
        if alert_time and (alert_time.hour < 6 or alert_time.hour > 20):
            suggestions['insufficient_monitoring'] = 0.65
        
        # Rule 5: Severity-based
        severity = alert.get('severity_id', 0)
        if severity >= 4:  # High/Critical
            if not suggestions:  # If no other hints
                suggestions['misconfiguration'] = 0.60
        
        # Rule 6: LOLBIN indicators
        if any(tool in finding_desc for tool in ['powershell', 'wmi', 'psexec', 'rundll32']):
            suggestions['defense_evasion'] = 0.80
        
        # Rule 7: API-related
        if any(word in finding_desc for word in ['api', 'endpoint', 'rest', 'graphql']):
            suggestions['api_security_gap'] = 0.70
        
        # Convert to binary suggestions (0/1) with confidence
        binary_suggestions = {}
        for category in self.CATEGORIES:
            if category in suggestions and suggestions[category] >= 0.6:
                binary_suggestions[category] = {
                    'suggested': 1,
                    'confidence': suggestions[category]
                }
            else:
                binary_suggestions[category] = {
                    'suggested': 0,
                    'confidence': 0.0
                }
        
        return binary_suggestions
    
    def train(self, X: np.ndarray, y: np.ndarray, feature_names: List[str] = None) -> Dict[str, Any]:
        """
        Train multi-label classifier
        
        Args:
            X: Features (n_samples, n_features)
            y: Labels (n_samples, 14)  # Binary matrix
            feature_names: Optional feature names for interpretability
            
        Returns:
            Training statistics
        """
        logger.info(f"Training Root Cause Analyzer on {len(X)} samples...")
        
        if feature_names:
            self.feature_names = feature_names
        
        # Check for class imbalance
        label_counts = y.sum(axis=0)
        logger.info("Label distribution:")
        for i, category in enumerate(self.CATEGORIES):
            count = int(label_counts[i])
            pct = (count / len(y) * 100)
            logger.info(f"  {category}: {count} ({pct:.1f}%)")
        
        # Train
        self.model.fit(X, y)
        self.trained = True
        
        # Store statistics
        self.train_stats = {
            'num_samples': len(X),
            'num_features': X.shape[1],
            'num_categories': len(self.CATEGORIES),
            'label_distribution': {
                category: int(count)
                for category, count in zip(self.CATEGORIES, label_counts)
            },
            'avg_labels_per_sample': float(y.sum(axis=1).mean())
        }
        
        logger.info(f"✅ Root Cause Analyzer trained successfully")
        logger.info(f"   Avg labels per alert: {self.train_stats['avg_labels_per_sample']:.2f}")
        
        return self.train_stats
    
    def predict(self, X: np.ndarray, return_proba: bool = True) -> np.ndarray:
        """
        Predict root causes
        
        Args:
            X: Features (n_samples, n_features)
            return_proba: If True, return probabilities; else binary predictions
            
        Returns:
            Predictions (n_samples, 14)
        """
        if not self.trained:
            raise ValueError("Model not trained! Call train() first.")
        
        if return_proba:
            # Get probabilities for positive class from each classifier
            proba = []
            for estimator in self.model.estimators_:
                # Get probability of class 1 (positive)
                proba.append(estimator.predict_proba(X)[:, 1])
            return np.array(proba).T
        else:
            return self.model.predict(X)
    
    def analyze_alert(self, features: np.ndarray, alert_context: Dict = None) -> Dict[str, Any]:
        """
        Complete analysis for single alert
        
        Args:
            features: Extracted features (1D array)
            alert_context: Optional context (timestamp, MITRE tactic, etc.)
            
        Returns:
            Complete root cause analysis with remediation
        """
        # Predict probabilities
        X = features.reshape(1, -1)
        probabilities = self.predict(X, return_proba=True)[0]
        
        # Build root causes list (threshold 0.5)
        root_causes = []
        for i, category in enumerate(self.CATEGORIES):
            if probabilities[i] >= 0.5:
                root_causes.append({
                    'cause': category,
                    'confidence': float(probabilities[i]),
                    'category_index': i
                })
        
        # Sort by confidence
        root_causes.sort(key=lambda x: -x['confidence'])
        
        # If no causes above threshold, take top 2
        if not root_causes:
            top_2_indices = np.argsort(probabilities)[-2:][::-1]
            for idx in top_2_indices:
                root_causes.append({
                    'cause': self.CATEGORIES[idx],
                    'confidence': float(probabilities[idx]),
                    'category_index': idx,
                    'below_threshold': True
                })
        
        # Determine priority using context
        if alert_context:
            root_causes = self._add_temporal_priority(root_causes, alert_context)
        
        # Generate remediation
        remediation = self._generate_remediation(root_causes)
        
        return {
            'num_root_causes': len(root_causes),
            'root_causes': root_causes,
            'dominant_cause': root_causes[0] if root_causes else None,
            'remediation': remediation,
            'all_probabilities': {
                category: float(prob)
                for category, prob in zip(self.CATEGORIES, probabilities)
            }
        }
    
    def _add_temporal_priority(self, root_causes: List[Dict], context: Dict) -> List[Dict]:
        """
        Add temporal priority to root causes
        
        Uses:
        - MITRE tactic ordering
        - Confidence scores
        - Attack stage
        """
        # Get tactic from context
        tactic = context.get('mitre_tactic', 'unknown')
        tactic_order = self.TACTIC_ORDER.get(tactic, 99)
        
        # Assign priority
        for cause_dict in root_causes:
            cause = cause_dict['cause']
            
            # Earlier tactics = likely origin
            if tactic_order <= 4:  # Early stages
                if cause in ['weak_credentials', 'unpatched_vulnerability', 'social_engineering']:
                    cause_dict['priority'] = 'primary'
                    cause_dict['temporal_order'] = 1
                else:
                    cause_dict['priority'] = 'contributing'
                    cause_dict['temporal_order'] = 2
            
            elif tactic_order <= 10:  # Mid stages
                if cause in ['inadequate_segmentation', 'excessive_privileges']:
                    cause_dict['priority'] = 'primary'
                    cause_dict['temporal_order'] = 2
                else:
                    cause_dict['priority'] = 'contributing'
                    cause_dict['temporal_order'] = 1
            
            else:  # Late stages
                if cause in ['insufficient_monitoring', 'defense_evasion']:
                    cause_dict['priority'] = 'consequence'
                    cause_dict['temporal_order'] = 3
                else:
                    cause_dict['priority'] = 'contributing'
                    cause_dict['temporal_order'] = 2
        
        # Re-sort by priority then confidence
        priority_weight = {'primary': 3, 'contributing': 2, 'consequence': 1}
        root_causes.sort(
            key=lambda x: (priority_weight.get(x.get('priority', 'contributing'), 2), x['confidence']),
            reverse=True
        )
        
        return root_causes
    
    def _generate_remediation(self, root_causes: List[Dict]) -> List[str]:
        """Generate prioritized remediation steps"""
        remediation = []
        
        REMEDIATION_MAP = {
            'weak_credentials': "Enforce strong password policy (12+ chars, complexity). Enable password breach monitoring.",
            'lack_of_mfa': "Enable MFA for all accounts, prioritize admin/privileged users.",
            'unpatched_vulnerability': "Apply security patches immediately. Implement automated patch management.",
            'misconfiguration': "Review and harden security configurations. Run security baseline audits.",
            'insufficient_monitoring': "Enable comprehensive logging. Deploy SIEM/EDR. Set up alerting rules.",
            'social_engineering': "Conduct security awareness training. Implement email filtering and anti-phishing controls.",
            'insider_threat': "Review user access logs. Implement DLP. Enable behavioral analytics.",
            'supply_chain': "Audit third-party vendors. Implement software composition analysis (SCA).",
            'zero_day_exploit': "Deploy virtual patching/Web Application Firewall. Segment affected systems.",
            'inadequate_segmentation': "Implement network segmentation. Deploy Zero Trust architecture.",
            'excessive_privileges': "Review and reduce user privileges. Implement least privilege principle.",
            'outdated_software': "Upgrade or replace end-of-life software. Create modernization roadmap.",
            'defense_evasion': "Monitor for LOLBIN abuse. Deploy behavioral detection. Harden system configurations.",
            'api_security_gap': "Implement API authentication/authorization. Enable rate limiting. Deploy API gateway."
        }
        
        for i, cause_dict in enumerate(root_causes[:3], 1):  # Top 3
            cause = cause_dict['cause']
            priority_label = cause_dict.get('priority', 'contributing')
            
            remedy = REMEDIATION_MAP.get(cause, "Conduct security review")
            remediation.append(f"{i}. [{priority_label.upper()}] {remedy}")
        
        return remediation
    
    def save(self, path: str = "models/root_cause_analyzer.pkl") -> None:
        """Save trained model"""
        if not self.trained:
            raise ValueError("Model not trained yet!")
        
        with open(path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'trained': self.trained,
                'feature_names': self.feature_names,
                'train_stats': self.train_stats,
                'categories': self.CATEGORIES
            }, f)
        
        logger.info(f"✅ Model saved to {path}")
    
    def load(self, path: str = "models/root_cause_analyzer.pkl") -> None:
        """Load trained model"""
        with open(path, 'rb') as f:
            data = pickle.load(f)
            self.model = data['model']
            self.trained = data['trained']
            self.feature_names = data['feature_names']
            self.train_stats = data['train_stats']
        
        logger.info(f"✅ Model loaded from {path}")


# Singleton
analyzer = RootCauseAnalyzer()
