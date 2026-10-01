"""
Stage Identifier - Rule-based Attack Stage Detection

Uses full 14 MITRE ATT&CK tactics (Enterprise Matrix)

NO 'unknown' stages - alerts without MITRE data are queued for review
"""

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class AttackStageIdentifier:
    """
    Identifies current attack stage from MITRE tactic enrichment
    
    Uses complete 14-tactic MITRE ATT&CK framework (not 10!)
    
    Critical stages (11-14):
    - Collection (TA0009)
    - Command and Control (TA0011)
    - Exfiltration (TA0010)
    - Impact (TA0040)
    """
    
    # Complete MITRE ATT&CK Enterprise tactics (14 total)
    MITRE_TACTICS = [
        {
            'stage': 1,
            'name': 'reconnaissance',
            'tactic_id': 'TA0043',
            'description': 'Gathering information to plan future operations',
            'criticality': 'low',
            'examples': ['Active Scanning', 'Search Open Websites', 'Phishing for Information']
        },
        {
            'stage': 2,
            'name': 'resource-development',
            'tactic_id': 'TA0042',
            'description': 'Establishing resources to support operations',
            'criticality': 'low',
            'examples': ['Acquire Infrastructure', 'Compromise Infrastructure', 'Develop Capabilities']
        },
        {
            'stage': 3,
            'name': 'initial-access',
            'tactic_id': 'TA0001',
            'description': 'Gaining initial foothold in the network',
            'criticality': 'medium',
            'examples': ['Phishing', 'Exploit Public-Facing Application', 'Valid Accounts']
        },
        {
            'stage': 4,
            'name': 'execution',
            'tactic_id': 'TA0002',
            'description': 'Running malicious code',
            'criticality': 'medium',
            'examples': ['PowerShell', 'Windows Management Instrumentation', 'Command-Line Interface']
        },
        {
            'stage': 5,
            'name': 'persistence',
            'tactic_id': 'TA0003',
            'description': 'Maintaining access across restarts',
            'criticality': 'high',
            'examples': ['Registry Run Keys', 'Scheduled Task', 'Create Account']
        },
        {
            'stage': 6,
            'name': 'privilege-escalation',
            'tactic_id': 'TA0004',
            'description': 'Obtaining higher-level permissions',
            'criticality': 'high',
            'examples': ['Process Injection', 'Valid Accounts', 'Exploitation for Privilege Escalation']
        },
        {
            'stage': 7,
            'name': 'defense-evasion',
            'tactic_id': 'TA0005',
            'description': 'Avoiding detection',
            'criticality': 'high',
            'examples': ['Obfuscated Files or Information', 'Disable Security Tools', 'Masquerading']
        },
        {
            'stage': 8,
            'name': 'credential-access',
            'tactic_id': 'TA0006',
            'description': 'Stealing credentials',
            'criticality': 'high',
            'examples': ['Credential Dumping', 'Brute Force', 'Input Capture']
        },
        {
            'stage': 9,
            'name': 'discovery',
            'tactic_id': 'TA0007',
            'description': 'Exploring the environment',
            'criticality': 'high',
            'examples': ['System Information Discovery', 'Network Service Scanning', 'Account Discovery']
        },
        {
            'stage': 10,
            'name': 'lateral-movement',
            'tactic_id': 'TA0008',
            'description': 'Moving through the environment',
            'criticality': 'high',
            'examples': ['Remote Services', 'SMB/Windows Admin Shares', 'Remote Desktop Protocol']
        },
        {
            'stage': 11,
            'name': 'collection',
            'tactic_id': 'TA0009',
            'description': 'Gathering data of interest',
            'criticality': 'critical',
            'examples': ['Data from Local System', 'Data from Network Shared Drive', 'Screen Capture']
        },
        {
            'stage': 12,
            'name': 'command-and-control',
            'tactic_id': 'TA0011',
            'description': 'Communicating with compromised systems',
            'criticality': 'critical',
            'examples': ['Web Service', 'Encrypted Channel', 'Proxy']
        },
        {
            'stage': 13,
            'name': 'exfiltration',
            'tactic_id': 'TA0010',
            'description': 'Stealing data',
            'criticality': 'critical',
            'examples': ['Exfiltration Over C2 Channel', 'Exfiltration to Cloud Storage']
        },
        {
            'stage': 14,
            'name': 'impact',
            'tactic_id': 'TA0040',
            'description': 'Disrupting availability or integrity',
            'criticality': 'critical',
            'examples': ['Data Encrypted for Impact', 'Service Stop', 'Defacement']
        }
    ]
    
    # Reverse mapping for fast lookup
    TACTIC_MAP = {tactic['name']: tactic for tactic in MITRE_TACTICS}
    TACTIC_ID_MAP = {tactic['tactic_id']: tactic for tactic in MITRE_TACTICS}
    
    def identify_stage(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Identify attack stage from MITRE tactic enrichment
        
        Args:
            alert: OCSF alert with MITRE enrichment
        
        Returns:
            Stage information with confidence
        
        NOTE: This method assumes alert has MITRE data!
              Alerts without MITRE should be queued BEFORE reaching here.
        """
        
        # Get MITRE enrichment data
        mitre_data = alert.get('enrichments', {}).get('mitre', {})
        
        # Try tactic name first (normalized to lowercase with hyphens)
        tactic_name = mitre_data.get('dominant_tactic')
        if tactic_name:
            # Normalize: lowercase and replace spaces/underscores with hyphens
            tactic_name = tactic_name.lower().replace(' ', '-').replace('_', '-')
            if tactic_name in self.TACTIC_MAP:
                stage_info = self.TACTIC_MAP[tactic_name]
                return self._build_result(stage_info, method='tactic_name', confidence=1.0)
        
        # Try tactic ID
        tactic_id = mitre_data.get('dominant_tactic_id') or mitre_data.get('tactic_id')
        if tactic_id and tactic_id in self.TACTIC_ID_MAP:
            stage_info = self.TACTIC_ID_MAP[tactic_id]
            return self._build_result(stage_info, method='tactic_id', confidence=1.0)
        
        # If we reach here, MITRE enrichment failed (should NOT happen!)
        logger.error(
            f"Alert {alert.get('alert_id')} has no valid MITRE tactic. "
            f"This should have been caught by queue system!"
        )
        
        # Emergency fallback - queue for review
        return {
            'current_stage': None,
            'stage_number': 0,
            'confidence': 0.0,
            'error': 'No MITRE tactic found',
            'action': 'QUEUE_FOR_REVIEW',
            'queue_reason': 'MITRE enrichment failed - requires manual mapping'
        }
    
    def _build_result(self, stage_info: Dict[str, Any], method: str, confidence: float) -> Dict[str, Any]:
        """Build standardized stage identification result"""
        
        return {
            'current_stage': stage_info['name'],
            'stage_number': stage_info['stage'],
            'tactic_id': stage_info['tactic_id'],
            'description': stage_info['description'],
            'criticality': stage_info['criticality'],
            'confidence': confidence,
            'method': method,
            'examples': stage_info['examples']
        }
    
    def get_next_stages(self, current_stage_number: int) -> Dict[str, Any]:
        """
        Get likely next stages in the attack kill chain
        
        Args:
            current_stage_number: Current stage (1-14)
        
        Returns:
            List of next stages or final stage message
        
        CRITICAL FIX: Properly handles stage 14 (Impact) as final stage
        """
        
        # SPECIAL CASE: Impact (Stage 14) is the FINAL stage
        if current_stage_number == 14:
            return {
                'next_stages': [],
                'is_final_stage': True,
                'message': (
                    'Final stage reached. Attack in IMPACT phase. '
                    'Immediate escalation and containment required!'
                ),
                'recommended_actions': [
                    'Activate incident response team immediately',
                    'Begin containment procedures',
                    'Preserve evidence for forensics',
                    'Notify executive team',
                    'Consider system isolation',
                    'Activate disaster recovery if needed'
                ]
            }
        
        # EDGE CASE: Invalid stage number
        if current_stage_number < 1 or current_stage_number > 14:
            logger.error(f"Invalid stage number: {current_stage_number}")
            return {
                'next_stages': [],
                'is_final_stage': False,
                'error': f'Invalid stage number: {current_stage_number}'
            }
        
        # Build next stages with probabilities
        next_stages = []
        
        for stage_info in self.MITRE_TACTICS:
            # Immediate next stage (most likely sequential progression)
            if stage_info['stage'] == current_stage_number + 1:
                next_stages.append({
                    'stage': stage_info['name'],
                    'stage_number': stage_info['stage'],
                    'tactic_id': stage_info['tactic_id'],
                    'description': stage_info['description'],
                    'criticality': stage_info['criticality'],
                    'probability': 0.85,
                    'reasoning': 'Sequential progression (most likely next stage)',
                    'examples': stage_info['examples']
                })
            
            # Skip one stage (less common, but attackers sometimes skip stages)
            elif stage_info['stage'] == current_stage_number + 2:
                next_stages.append({
                    'stage': stage_info['name'],
                    'stage_number': stage_info['stage'],
                    'tactic_id': stage_info['tactic_id'],
                    'description': stage_info['description'],
                    'criticality': stage_info['criticality'],
                    'probability': 0.35,
                    'reasoning': 'Possible skip in kill chain (less common)',
                    'examples': stage_info['examples']
                })
            
            # Skip two stages (rare, but plausible for fast-moving attacks)
            elif stage_info['stage'] == current_stage_number + 3:
                next_stages.append({
                    'stage': stage_info['name'],
                    'stage_number': stage_info['stage'],
                    'tactic_id': stage_info['tactic_id'],
                    'description': stage_info['description'],
                    'criticality': stage_info['criticality'],
                    'probability': 0.15,
                    'reasoning': 'Rare skip (attacker moving fast or automated tool)',
                    'examples': stage_info['examples']
                })
        
        return {
            'next_stages': next_stages,
            'is_final_stage': False
        }
    
    def get_stage_info(self, stage_number: int) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific stage"""
        
        for stage in self.MITRE_TACTICS:
            if stage['stage'] == stage_number:
                return stage
        
        return None
    
    def get_all_critical_stages(self) -> List[Dict[str, Any]]:
        """Get all critical stages (11-14) for escalation rules"""
        
        return [
            stage for stage in self.MITRE_TACTICS
            if stage['criticality'] == 'critical'
        ]
