"""
Alert Processor

Orchestrates alert enrichment + FP detection + queue assignment + correlation.
Also includes auto-ingest hook for historical_incidents Qdrant collection:
  when an analyst closes/resolves an alert, index_resolved_alert() persists it
  into the KB for future MMR retrieval by the reasoning agent.
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from pymongo import MongoClient

from backend.services.ml.false_positive_detection.fp_detector import FalsePositiveDetector
from backend.services.enrichment.mitre_enrichment_service import get_mitre_enrichment_service
from backend.services.enrichment.threat_intel_service import get_threat_intel_service
from backend.services.knowledge_base import kb_service

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AlertProcessor:
    """
    Process alerts through enrichment, FP detection, queue assignment, and correlation.
    
    Flow:
    1. Enrich with MITRE, Threat Intel
    2. Detect false positives
    3. Assign to appropriate queue
    4. Store
    5. Correlate (quick + deep background)
    6. Notify queue
    """
    
    def __init__(self, db_client=None, redis_client=None):
        # PyMongo objects do not support truthiness checks, so avoid `db_client or ...`.
        if db_client is None:
            self.db = MongoClient()["soar_db"]
        else:
            # Allow either a MongoClient or an already-selected database handle.
            try:
                self.db = db_client["soar_db"]  # type: ignore[index]
            except Exception:
                self.db = db_client
        self.fp_detector = FalsePositiveDetector(db_client=self.db)
        self.mitre_service = get_mitre_enrichment_service()
        self.threat_intel = get_threat_intel_service()
        
        # Correlation engine (hybrid: quick + background deep)
        from backend.services.correlation import HybridCorrelationSystem
        self.correlation_system = HybridCorrelationSystem(
            db_client=self.db,
            redis_client=redis_client,
        )

    async def start(self) -> None:
        """
        Startup hook for the stream worker.

        The stream worker expects the processor to expose an async `start()` method
        to kick off any background workers (e.g. deep correlation).
        """
        try:
            self.correlation_system.start()
        except Exception as e:
            logger.warning(f"AlertProcessor.start(): correlation start failed (non-fatal): {e}")
        
    async def process_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process alert end-to-end
        
        Args:
            alert: OCSF ULF alert
            
        Returns:
            Processed alert with enrichments and queue assignment
        """
        logger.info(f"Processing alert {alert.get('alert_id')}")
        
        try:
            # Step 1: MITRE Enrichment
            alert = await self._enrich_mitre(alert)
            
            # Step 2: Threat Intelligence Enrichment
            alert = await self._enrich_threat_intel(alert)
            
            # Step 3: FP Detection
            alert = self._detect_false_positive(alert)
            
            # Step 4: Queue Assignment
            alert = self._assign_queue(alert)
            
            # Step 5: Store
            await self._store_alert(alert)
            
            # Step 5.5: Correlation (quick is awaited; deep is backgrounded)
            try:
                correlation_result = await self.correlation_system.handle_alert(alert)
                alert['correlation'] = {
                    'quick': [r.model_dump() for r in correlation_result.quick_correlations],
                    'incident_id': correlation_result.incident_id,
                    'deep_queued': correlation_result.deep_queued,
                }
            except Exception as ce:
                logger.warning(f"Correlation failed (non-fatal): {ce}")
                alert['correlation'] = {'quick': [], 'incident_id': None, 'deep_queued': False}
            
            # Step 6: Notify queue (can be async)
            await self._notify_queue(alert)
            
            logger.info(f"Alert {alert.get('alert_id')} processed → {alert['queue_assignment']}")
            
            return alert
            
        except Exception as e:
            logger.error(f"Error processing alert {alert.get('alert_id')}: {e}", exc_info=True)
            # Store as failed
            alert['processing_status'] = 'failed'
            alert['processing_error'] = str(e)
            await self._store_alert(alert)
            raise
    
    async def _enrich_mitre(self, alert: Dict) -> Dict:
        """Enrich with MITRE ATT&CK data (3-layer semantic pipeline)."""
        try:
            if not alert.get('enrichments'):
                alert['enrichments'] = {}

            self.mitre_service.enrich(alert)  # modifies alert in-place
            enrichment = alert['enrichments'].get('mitre', {})

            logger.debug(
                f"MITRE enrichment: {enrichment.get('technique_id')} "
                f"({enrichment.get('technique_name')}) via {enrichment.get('mapping_method')}"
            )

        except Exception as e:
            logger.warning(f"MITRE enrichment failed: {e}")
            if not alert.get('enrichments'):
                alert['enrichments'] = {}
            alert['enrichments']['mitre'] = {'error': str(e)}

        return alert
    
    async def _enrich_threat_intel(self, alert: Dict) -> Dict:
        """Enrich with threat intelligence from all 9 providers in parallel."""
        try:
            if not alert.get('enrichments'):
                alert['enrichments'] = {}

            # Full alert-aware enrichment (extracts IPs, hashes, domains)
            await self.threat_intel.enrich_alert(alert)  # modifies alert in-place

            ti = alert['enrichments'].get('threat_intel', {})
            logger.info(
                f"TI enrichment: score={ti.get('aggregate_score', 0):.2f}, "
                f"malicious={ti.get('is_malicious', False)}"
            )

        except Exception as e:
            logger.warning(f"Threat intel enrichment failed: {e}")
            if not alert.get('enrichments'):
                alert['enrichments'] = {}
            alert['enrichments']['threat_intel'] = {
                'error': str(e),
                'aggregate_score': 0.0,
                'is_malicious': False,
            }

        return alert
    
    def _detect_false_positive(self, alert: Dict) -> Dict:
        """Run FP detection"""
        try:
            fp_analysis = self.fp_detector.detect(alert)
            alert['fp_analysis'] = fp_analysis
            
            logger.info(f"FP Score: {fp_analysis['fp_score']:.2f}, "
                       f"Action: {fp_analysis['recommendation']['action']}")
            
        except Exception as e:
            logger.error(f"FP detection failed: {e}", exc_info=True)
            alert['fp_analysis'] = {
                'error': str(e),
                'fp_score': 0.0,
                'recommendation': {'action': 'investigate', 'priority': 'medium'}
            }
        
        return alert
    
    def _assign_queue(self, alert: Dict) -> Dict:
        """Assign alert to appropriate queue"""
        fp_analysis = alert.get('fp_analysis', {})
        action = fp_analysis.get('recommendation', {}).get('action', 'investigate')
        
        # Queue assignment logic
        if action == 'auto_close':
            queue = 'auto_closed'
            alert['status'] = 'auto_closed_fp'
            alert['visible_in_soc_queue'] = False
            alert['visible_in_fp_review_queue'] = False
            
        elif action == 'suppress':
            queue = 'fp_review_queue'
            alert['status'] = 'suppressed'
            alert['visible_in_soc_queue'] = False
            alert['visible_in_fp_review_queue'] = True
            
        else:  # investigate, deprioritize
            queue = 'soc_queue'
            alert['status'] = 'open'
            alert['visible_in_soc_queue'] = True
            alert['visible_in_fp_review_queue'] = False
        
        alert['queue_assignment'] = queue
        alert['assigned_at'] = datetime.now()
        
        return alert
    
    async def _store_alert(self, alert: Dict):
        """Store alert in MongoDB"""
        alert['processed_at'] = datetime.now()
        
        # Upsert (insert or update)
        self.db.alerts.update_one(
            {'alert_id': alert['alert_id']},
            {'$set': alert},
            upsert=True
        )
    
    async def _notify_queue(self, alert: Dict):
        """Notify relevant queue/consumers (webhook, email, etc.)"""
        queue = alert['queue_assignment']
        
        # For now, just log
        # In production: send webhook, email, Slack notification, etc.
        logger.info(f"Alert queued to {queue}: {alert['alert_id']}")
        
        # Future: Implement actual notifications
        # if queue == 'soc_queue':
        #     await self.notifications.send_soc_alert(alert)
        # elif queue == 'fp_review_queue':
        #     await self.notifications.send_fp_review(alert)

    async def index_resolved_alert(
        self,
        alert: Dict[str, Any],
        resolution: str,
        outcome: str = "resolved",
        analyst_approved: bool = True,
    ) -> bool:
        """
        Auto-ingest hook — call this when an analyst closes/resolves an alert.

        Embeds the incident into the `historical_incidents` Qdrant collection
        so future alerts can retrieve MMR-diverse similar past cases.

        Args:
            alert:            The fully-enriched alert dict (must have alert_id, severity, etc.)
            resolution:       Free-text analyst resolution notes (e.g. "Blocked IP, reset MFA")
            outcome:          "resolved" | "false_positive" | "escalated"
            analyst_approved: True if analyst explicitly approved this incident record

        Returns:
            True on success, False on failure (never raises).
        """
        mitre_enrichment = alert.get("enrichments", {}).get("mitre", {})
        technique_id = (
            mitre_enrichment.get("technique_id")
            or alert.get("technique_id")
            or ""
        )

        incident = {
            "incident_id":      alert.get("alert_id", ""),
            "summary":          (
                f"{alert.get('attack_type', alert.get('finding', {}).get('title', 'Security incident'))} "
                f"detected on {alert.get('asset_id', alert.get('src_endpoint', {}).get('hostname', 'unknown host'))}. "
                f"Severity: {alert.get('severity', 'medium')}."
            ),
            "mitre_technique":  technique_id,
            "resolution":       resolution,
            "outcome":          outcome,
            "analyst_approved": analyst_approved,
            "severity":         alert.get("severity", "medium"),
            "asset_type":       alert.get("asset_type", ""),
            "source_ip":        (
                alert.get("src_endpoint", {}).get("ip")
                or alert.get("source_ip", "")
            ),
            "timestamp":        datetime.utcnow().timestamp(),
        }

        try:
            # Fire-and-forget: don't await to block the API response
            success = await kb_service.index_incident(incident)
            if success:
                logger.info(
                    f"Auto-indexed resolved alert {incident['incident_id']} "
                    f"(technique={technique_id}) into historical_incidents KB"
                )
            else:
                logger.warning(
                    f"Failed to index resolved alert {incident['incident_id']} — "
                    f"KB upsert returned False"
                )
            return success
        except Exception as e:
            logger.error(
                f"Exception indexing resolved alert {alert.get('alert_id')}: {e}",
                exc_info=True,
            )
            return False


async def test_processor():
    """Test alert processor with sample alert"""
    from datetime import datetime
    
    sample_alert = {
        "alert_id": "test_processor_001",
        "time": int(datetime.now().timestamp() * 1000),
        "severity_id": 2,
        "class_uid": 4001,
        "finding": {
            "title": "Network scan from 10.0.0.50",
            "desc": "Port scan detected",
            "uid": "test_001"
        },
        "src_endpoint": {
            "ip": "10.0.0.50",
            "hostname": "nessus-scanner-01"
        },
        "dst_endpoint": {
            "hostname": "web-server-01"
        },
        "unmapped": {
            "wazuh_rule_id": 40111,
            "wazuh_rule_level": 7
        }
    }
    
    processor = AlertProcessor()
    result = await processor.process_alert(sample_alert)
    
    print("\n" + "="*60)
    print("ALERT PROCESSOR TEST RESULTS")
    print("="*60)
    print(f"Alert ID: {result['alert_id']}")
    print(f"Queue: {result['queue_assignment']}")
    print(f"FP Score: {result['fp_analysis']['fp_score']:.2f}")
    print(f"Action: {result['fp_analysis']['recommendation']['action']}")
    print(f"Visible in SOC: {result['visible_in_soc_queue']}")
    print("="*60)


if __name__ == "__main__":
    import asyncio
    asyncio.run(test_processor())
