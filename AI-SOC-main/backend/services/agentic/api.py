"""
FastAPI Entrypoint for Agentic SOAR System
Webhook for receiving enriched alerts from main SOAR platform
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Any, Optional
from datetime import datetime
import logging

from .workflows.orchestrator import agentic_workflow
from .tools.mongodb_helper import mongodb_helper

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="Agentic SOAR API",
    description="Autonomous incident response with LLM-powered agents",
    version="1.0.0"
)


class AlertWebhook(BaseModel):
    """Webhook payload schema"""
    alert_id: str
    alert: Dict[str, Any]
    priority: Optional[str] = None


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": "Agentic SOAR",
        "status": "running",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/health")
async def health():
    """Detailed health check"""
    return {
        "status": "healthy",
        "components": {
            "workflow": "ok",
            "mongodb": "ok",  # TODO: Add actual check
            "redis": "ok",    # TODO: Add actual check
            "qdrant": "ok"    # TODO: Add actual check
        },
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/webhook/alert")
async def receive_alert(
    webhook: AlertWebhook,
    background_tasks: BackgroundTasks
):
    """
    Receive enriched alert from main SOAR platform.
    
    Process alert asynchronously through the agent workflow.
    
    Args:
        webhook: Alert payload
        background_tasks: FastAPI background tasks
        
    Returns:
        Acknowledgment with incident ID
    """
    
    logger.info(f"Received alert: {webhook.alert_id}")
    
    try:
        # Validate alert has required fields
        if "severity" not in webhook.alert:
            raise HTTPException(status_code=400, detail="Alert missing 'severity' field")
        
        # Process in background
        background_tasks.add_task(
            process_alert_async,
            webhook.alert_id,
            webhook.alert
        )
        
        return {
            "status": "accepted",
            "incident_id": webhook.alert_id,
            "message": "Alert accepted for processing",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error receiving alert: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


async def process_alert_async(alert_id: str, alert: Dict[str, Any]):
    """
    Process alert through agent workflow (background task).
    
    Args:
        alert_id: Alert identifier
        alert: Enriched alert data
    """
    
    try:
        logger.info(f"Starting workflow for {alert_id}")
        
        # Process through agentic workflow
        final_state = await agentic_workflow.process_alert(alert)
        
        # Log result
        decision = final_state.get("decision", "UNKNOWN")
        logger.info(f"Workflow complete for {alert_id}: {decision}")
        
        # Audit log entry
        audit_entry = {
            "incident_id": alert_id,
            "decision": decision,
            "processing_time": final_state.get("total_processing_time_seconds"),
            "timestamp": datetime.utcnow(),
            "report": final_state.get("report")
        }
        
        mongodb_helper.save_audit_log(audit_entry)
        
    except Exception as e:
        logger.error(f"Error processing {alert_id}: {e}", exc_info=True)
        
        # Save error to audit log
        error_entry = {
            "incident_id": alert_id,
            "decision": "ERROR",
            "error": str(e),
            "timestamp": datetime.utcnow()
        }
        mongodb_helper.save_audit_log(error_entry)


@app.get("/status/{incident_id}")
async def get_incident_status(incident_id: str):
    """
    Get status of an incident.
    
    Args:
        incident_id: Incident identifier
        
    Returns:
        Incident status and report
    """
    
    try:
        # Retrieve from MongoDB
        incident = mongodb_helper.get_incident(incident_id)
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        return {
            "incident_id": incident_id,
            "status": incident.get("status"),
            "decision": incident.get("decision"),
            "priority": incident.get("priority"),
            "report": incident.get("report"),
            "created_at": incident.get("created_at"),
            "updated_at": incident.get("updated_at")
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving incident: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/process/batch")
async def process_batch_alerts(
    alerts: list[AlertWebhook],
    background_tasks: BackgroundTasks
):
    """
    Process multiple alerts in batch.
    
    Args:
        alerts: List of alerts
        background_tasks: FastAPI background tasks
        
    Returns:
        Batch processing acknowledgment
    """
    
    logger.info(f"Received batch of {len(alerts)} alerts")
    
    try:
        # Process all in background
        background_tasks.add_task(
            process_batch_async,
            [a.model_dump() for a in alerts]
        )
        
        return {
            "status": "accepted",
            "count": len(alerts),
            "message": f"Batch of {len(alerts)} alerts accepted for processing",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error receiving batch: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


async def process_batch_async(alerts: list[Dict[str, Any]]):
    """Process batch of alerts (background task)"""
    
    try:
        logger.info(f"Processing batch of {len(alerts)} alerts")
        
        # Extract alert data
        alert_data = [a["alert"] for a in alerts]
        
        # Process through workflow
        results = await agentic_workflow.process_batch(alert_data)
        
        logger.info(f"Batch processing complete: {len(results)} results")
        
    except Exception as e:
        logger.error(f"Error processing batch: {e}", exc_info=True)


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "backend.services.agentic.api:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
