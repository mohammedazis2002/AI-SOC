"""
Enhanced MITRE Enricher

Multi-method MITRE ATT&CK enrichment to minimize unmapped alerts

Methods (in order of preference):
1. Direct SIEM MITRE data (if available)
2. Sigma rule mapping
3. Pattern matching against technique library
4. Process/command analysis
5. Network behavior analysis

Goal: Enrich as many alerts as possible to avoid queuing
"""

import logging
import re
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)


class MITREEnricher:
    """
    Enhanced MITREenrichment with multiple fallback methods
    
    Reduces 'unknown' stages by trying 5 different enrichment methods
    before giving up and queuing the alert
    """
    
    def __init__(self, pattern_library_path: Optional[str] = None):
        """
        Initialize MITRE enricher
        
        Args:
            pattern_library_path: Path to MITRE pattern library JSON
        """
        self.pattern_library = self._load_pattern_library(pattern_library_path)
        
        # Track enrichment method success rates
        self.method_stats = {
            'siem_data': 0,
            'sigma_mapping': 0,
            'pattern_matching': 0,
            'process_analysis': 0,
            'network_analysis': 0,
            'failed': 0
        }
    
    def _load_pattern_library(self, path: Optional[str]) -> Dict[str, Any]:
        """Load MITRE pattern matching library"""
        
        if not path:
            logger.warning("No pattern library provided. Pattern matching will be limited.")
            return self._get_basic_patterns()
        
        try:
            import json
            with open(path, 'r') as f:
                library = json.load(f)
            logger.info(f"Loaded MITRE pattern library with {len(library)} patterns")
            return library
        except Exception as e:
            logger.error(f"Failed to load pattern library: {e}. Using basic patterns.")
            return self._get_basic_patterns()
    
    def _get_basic_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get basic MITRE pattern mappings
        
        This is a simplified version - production should have comprehensive patterns
        """
        
        return {
            'reconnaissance': [
                {'keywords': ['port scan', 'network scan', 'reconnaissance'], 'confidence': 0.9},
                {'keywords': ['nmap', 'masscan'], 'confidence': 0.95}
            ],
            'initial-access': [
                {'keywords': ['phishing', 'exploit', 'brute force', 'valid accounts'], 'confidence': 0.85},
                {'keywords': ['rdp', 'ssh'], 'confidence': 0.7}
            ],
            'execution': [
                {'keywords': ['powershell', 'cmd.exe', 'wscript', 'cscript'], 'confidence': 0.8},
                {'keywords': ['bash', 'python', 'perl'], 'confidence': 0.75}
            ],
            'persistence': [
                {'keywords': ['registry', 'scheduled task', 'startup', 'service creation'], 'confidence': 0.85},
                {'keywords': ['cron', 'systemd'], 'confidence': 0.8}
            ],
            'privilege-escalation': [
                {'keywords': ['uac bypass', 'sudo', 'privilege escalation', 'token manipulation'], 'confidence': 0.9},
                {'keywords': ['setuid', 'exploit'], 'confidence': 0.7}
            ],
            'defense-evasion': [
                {'keywords': ['obfuscation', 'disable', 'clear log', 'timestomp'], 'confidence': 0.85},
                {'keywords': ['encoding', 'encryption'], 'confidence': 0.6}
            ],
            'credential-access': [
                {'keywords': ['mimikatz', 'credential dump', 'password', 'lsass'], 'confidence': 0.95},
                {'keywords': ['keylogger', 'brute force'], 'confidence': 0.8}
            ],
            'discovery': [
                {'keywords': ['whoami', 'ipconfig', 'netstat', 'tasklist', 'arp'], 'confidence': 0.9},
                {'keywords': ['query', 'enumerate'], 'confidence': 0.7}
            ],
            'lateral-movement': [
                {'keywords': ['psexec', 'wmic', 'rdp', 'smb', 'winrm'], 'confidence': 0.9},
                {'keywords': ['remote', 'lateral'], 'confidence': 0.7}
            ],
            'collection': [
                {'keywords': ['data staged', 'screenshot', 'clipboard', 'archive'], 'confidence': 0.85},
                {'keywords': ['collect', 'gather'], 'confidence': 0.6}
            ],
            'command-and-control': [
                {'keywords': ['c2', 'beacon', 'callback', 'tunnel'], 'confidence': 0.9},
                {'keywords': ['dns tunneling', 'covert channel'], 'confidence': 0.85}
            ],
            'exfiltration': [
                {'keywords': ['exfiltration', 'data transfer', 'upload'], 'confidence': 0.9},
                {'keywords': ['ftp', 'cloud storage'], 'confidence': 0.7}
            ],
            'impact': [
                {'keywords': ['ransomware', 'wiper', 'encrypt', 'delete', 'destroy'], 'confidence': 0.95},
                {'keywords': ['denial of service', 'defacement'], 'confidence': 0.85}
            ]
        }
    
    def enrich(self, alert: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Dict[str, bool]]:
        """
        Enrich alert with MITRE data using multiple methods
        
        Args:
            alert: Alert to enrich
        
        Returns:
            Tuple of (MITRE enrichment dict or None, enrichment attempts dict)
        """
        
        enrichment_attempts = {
            'siem_data': False,
            'sigma_mapping': False,
            'pattern_matching': False,
            'process_analysis': False,
            'network_analysis': False
        }
        
        # Method 1: Check if SIEM already provided MITRE data
        mitre_data = self._method_1_siem_data(alert)
        if mitre_data:
            enrichment_attempts['siem_data'] = True
            self.method_stats['siem_data'] += 1
            return (mitre_data, enrichment_attempts)
        
        # Method 2: Sigma rule mapping
        enrichment_attempts['sigma_mapping'] = True
        mitre_data = self._method_2_sigma_mapping(alert)
        if mitre_data:
            self.method_stats['sigma_mapping'] += 1
            return (mitre_data, enrichment_attempts)
        
        # Method 3: Pattern matching
        enrichment_attempts['pattern_matching'] = True
        mitre_data = self._method_3_pattern_matching(alert)
        if mitre_data:
            self.method_stats['pattern_matching'] += 1
            return (mitre_data, enrichment_attempts)
        
        # Method 4: Process/command analysis
        enrichment_attempts['process_analysis'] = True
        mitre_data = self._method_4_process_analysis(alert)
        if mitre_data:
            self.method_stats['process_analysis'] += 1
            return (mitre_data, enrichment_attempts)
        
        # Method 5: Network behavior analysis
        enrichment_attempts['network_analysis'] = True
        mitre_data = self._method_5_network_analysis(alert)
        if mitre_data:
            self.method_stats['network_analysis'] += 1
            return (mitre_data, enrichment_attempts)
        
        # All methods failed
        self.method_stats['failed'] += 1
        logger.warning(f"Alert {alert.get('alert_id')} - all MITRE enrichment methods failed")
        return (None, enrichment_attempts)
    
    def _method_1_siem_data(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Method 1: Extract MITRE data already provided by SIEM"""
        
        # Check if alert already has MITRE enrichment
        existing_mitre = alert.get('enrichments', {}).get('mitre', {})
        
        if existing_mitre and existing_mitre.get('dominant_tactic'):
            logger.debug(f"Alert {alert.get('alert_id')} - using existing SIEM MITRE data")
            return existing_mitre
        
        return None
    
    def _method_2_sigma_mapping(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Method 2: Map via Sigma rule if rule ID is present"""
        
        # Check if alert has Sigma rule information
        rule_id = alert.get('metadata', {}).get('rule_id') or alert.get('rule', {}).get('id')
        
        if not rule_id:
            return None
        
        # TODO: Implement Sigma rule -> MITRE mapping database lookup
        # For now, return None
        logger.debug(f"Alert {alert.get('alert_id')} - Sigma mapping not yet implemented")
        return None
    
    def _method_3_pattern_matching(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Method 3: Pattern matching against technique library"""
        
        # Extract text fields to search
        search_text = ' '.join([
            alert.get('message', ''),
            alert.get('class_name', ''),
            str(alert.get('metadata', {})),
            str(alert.get('process', {}))
        ]).lower()
        
        best_match = None
        best_confidence = 0.0
        
        for tactic, patterns in self.pattern_library.items():
            for pattern in patterns:
                keywords = pattern.get('keywords', [])
                
                # Check if any keywords match
                matches = sum(1 for keyword in keywords if keyword in search_text)
                
                if matches > 0:
                    # Calculate match score
                    match_ratio = matches / len(keywords)
                    confidence = pattern.get('confidence', 0.5) * match_ratio
                    
                    if confidence > best_confidence:
                        best_confidence = confidence
                        best_match = tactic
        
        if best_match and best_confidence >= 0.5:  # Minimum 50% match ratio
            logger.debug(
                f"Alert {alert.get('alert_id')} - pattern match: {best_match}"
            )
            return {
                'dominant_tactic': best_match,
                'method': 'pattern_matching'
            }
        
        return None
    
    def _method_4_process_analysis(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Method 4: Analyze process/command line for MITRE indicators"""
        
        process_info = alert.get('process', {})
        command_line = process_info.get('cmd_line', '') or process_info.get('command_line', '')
        
        if not command_line:
            return None
        
        command_line = command_line.lower()
        
        # Common execution patterns
        if any(cmd in command_line for cmd in ['powershell', 'cmd.exe', 'wscript', 'cscript']):
            return {
                'dominant_tactic': 'execution',
                'method': 'process_analysis'
            }
        
        # Credential access patterns
        if any(cmd in command_line for cmd in ['mimikatz', 'lsass', 'sekurlsa']):
            return {
                'dominant_tactic': 'credential-access',
                'method': 'process_analysis'
            }
        
        # Discovery patterns
        if any(cmd in command_line for cmd in ['whoami', 'net user', 'ipconfig', 'netstat']):
            return {
                'dominant_tactic': 'discovery',
                'method': 'process_analysis'
            }
        
        # Persistence patterns
        if any(cmd in command_line for cmd in ['schtasks', 'reg add', 'sc create']):
            return {
                'dominant_tactic': 'persistence',
                'method': 'process_analysis'
            }
        
        return None
    
    def _method_5_network_analysis(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Method 5: Analyze network behavior for MITRE indicators"""
        
        # Check for port scanning (reconnaissance)
        if alert.get('class_name') == 'port_scan' or 'scan' in alert.get('message', '').lower():
            return {
                'dominant_tactic': 'reconnaissance',
                'method': 'network_analysis'
            }
        
        # Check for C2 indicators
        # Look for suspicious domains, DNS tunneling, etc.
        network = alert.get('network', {}) or alert.get('dst_endpoint', {})
        domain = network.get('domain', '')
        
        if domain:
            # Simple C2 domain heuristics (production would use threat intel)
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                return {
                    'dominant_tactic': 'command-and-control',
                    'method': 'network_analysis'
                }
        
        # Check for data exfiltration patterns
        # Large outbound data transfer, uncommon protocols, etc.
        bytes_out = alert.get('traffic', {}).get('bytes_out', 0)
        if bytes_out > 100 * 1024 * 1024:  # > 100MB outbound
            return {
                'dominant_tactic': 'exfiltration',
                'method': 'network_analysis'
            }
        
        return None
    
    def get_enrichment_stats(self) -> Dict[str, Any]:
        """Get statistics on enrichment method success rates"""
        
        total = sum(self.method_stats.values())
        
        if total == 0:
            return {'total_attempts': 0}
        
        return {
            'total_attempts': total,
            'success_rate': (total - self.method_stats['failed']) / total,
            'method_breakdown': {
                method: {
                    'count': count,
                    'percentage': (count / total) * 100
                }
                for method, count in self.method_stats.items()
            }
        }
