"""
Intelligent Log Processor
Routes alerts to the appropriate mapper based on source
"""

from typing import Dict, Any, Tuple, List
from schemas.ulf_schema import UnifiedLogFormat

from services.ingestion.wazuh_mapper import WazuhToULFMapper
from services.ingestion.sentinelone_mapper import SentinelOneMapper
from services.ingestion.ai_mapper import AIMapper


class LogProcessor:
    """
    Intelligent alert processor that routes to appropriate mapper
    
    Flow:
    1. Identify alert source
    2. Route to rule-based mapper (Wazuh, SentinelOne) OR AI mapper
    3. Return normalized ULF
    """
    
    def __init__(self):
        self.wazuh_mapper = WazuhToULFMapper()
        self.s1_mapper = SentinelOneMapper()
        self.ai_mapper = AIMapper()
    
    async def process_alert(
        self, 
        raw_alert: Dict[str, Any], 
        source: str
    ) -> Tuple[UnifiedLogFormat, List[str], Dict[str, Any], str]:
        """
        Process alert with appropriate mapper
        
        Args:
            raw_alert: Raw alert dictionary
            source: Source identifier (wazuh, sentinelone, unknown)
        
        Returns:
            Tuple of (ULF, warnings, summary, mapper_used)
        """
        
        source_lower = source.lower()
        
        # Route to appropriate mapper
        if source_lower == "wazuh" or self._is_wazuh_alert(raw_alert):
            print(f"Using rule-based Wazuh mapper")
            ulf, warnings, summary = self.wazuh_mapper.map_alert(raw_alert)
            mapper_used = "wazuh_rule_based"
        
        elif source_lower == "sentinelone" or self._is_sentinelone_alert(raw_alert):
            print(f"Using rule-based SentinelOne mapper")
            ulf, warnings, summary = self.s1_mapper.map_alert(raw_alert)
            mapper_used = "sentinelone_rule_based"
        
        # Add more SIEM mappers here as needed:
        # elif source_lower == "sumologic":
        #     ulf, warnings, summary = self.sumologic_mapper.map_alert(raw_alert)
        #     mapper_used = "sumologic_rule_based"
        
        else:
            # Unknown format - use AI mapper
            print(f"��� Using AI-assisted mapper for unknown format")
            
            # Convert dict to string for AI processing
            if isinstance(raw_alert, dict):
                import json
                raw_log = json.dumps(raw_alert, indent=2)
            else:
                raw_log = str(raw_alert)
            
            ulf, confidence = await self.ai_mapper.map_to_ulf(raw_log, source)
            warnings = [f"AI confidence: {confidence:.2f}"]
            
            from schemas.ulf_schema import get_validation_summary
            summary = get_validation_summary(ulf)
            summary["ai_confidence"] = confidence
            
            mapper_used = "ai_assisted"
        
        # MITRE enrichment happens downstream in alert_pipeline.py (3-layer semantic enrichment)
        # Convert ULF to dict if needed
        if hasattr(ulf, 'dict'):
            ulf_dict = ulf.dict()
        else:
            ulf_dict = ulf
        
        summary['mitre_tactics'] = []
        summary['dominant_tactic'] = 'pending_enrichment'
        
        return ulf_dict, warnings, summary, mapper_used
    
    def _is_wazuh_alert(self, alert: Dict[str, Any]) -> bool:
        """Detect if alert is from Wazuh"""
        # Wazuh alerts have specific structure
        return (
            "rule" in alert and 
            "agent" in alert and
            isinstance(alert.get("rule"), dict) and
            "level" in alert.get("rule", {})
        )
    
    def _is_sentinelone_alert(self, alert: Dict[str, Any]) -> bool:
        """Detect if alert is from SentinelOne"""
        return (
            "threatInfo" in alert or
            "agentRealtimeInfo" in alert
        )


# Test the processor
async def test_log_processor():
    """Test log processor with different alert types"""
    import json
    
    processor = LogProcessor()
    
    # Test 1: Wazuh alert
    print("\n" + "="*80)
    print("TEST 1: Wazuh Alert")
    print("="*80)
    
    wazuh_alert = {
        "rule": {"level": 10, "description": "SSH brute force"},
        "agent": {"name": "server-01", "ip": "10.0.1.50"},
        "data": {"srcip": "1.2.3.4"},
        "timestamp": "2024-12-30T10:00:00Z",
        "id": "12345"
    }
    
    ulf1, warnings1, summary1, mapper1 = await processor.process_alert(
        wazuh_alert, 
        "unknown"  # Even with "unknown", it should detect Wazuh
    )
    
    print(f"Mapper used: {mapper1}")
    print(f"Alert ID: {ulf1.alert_id}")
    print(f"Severity: {ulf1.severity}")
    
    # Test 2: SentinelOne alert
    print("\n" + "="*80)
    print("TEST 2: SentinelOne Alert")
    print("="*80)
    
    s1_alert = {
        "threatInfo": {
            "threatName": "Malware.Generic",
            "confidenceLevel": "malicious"
        },
        "agentRealtimeInfo": {
            "agentComputerName": "DESKTOP-123"
        },
        "indicators": [{"category": "Network", "value": "1.2.3.4"}],
        "id": "s1-67890"
    }
    
    ulf2, warnings2, summary2, mapper2 = await processor.process_alert(
        s1_alert,
        "sentinelone"
    )
    
    print(f"Mapper used: {mapper2}")
    print(f"Alert ID: {ulf2.alert_id}")
    print(f"Severity: {ulf2.severity}")
    
    # Test 3: Unknown format (AI mapper)
    print("\n" + "="*80)
    print("TEST 3: Unknown Format (AI Mapper)")
    print("="*80)
    
    unknown_alert = {
        "message": "Failed login attempt from 1.2.3.4",
        "timestamp": "2024-12-30T10:00:00Z"
    }
    
    ulf3, warnings3, summary3, mapper3 = await processor.process_alert(
        unknown_alert,
        "custom_system"
    )
    
    print(f"Mapper used: {mapper3}")
    print(f"Alert ID: {ulf3.alert_id}")
    print(f"Warnings: {warnings3}")


if __name__ == "__main__":
    import asyncio
    asyncio.run(test_log_processor())
