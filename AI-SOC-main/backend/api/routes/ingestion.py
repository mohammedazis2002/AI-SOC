"""
Alert Ingestion API Routes with Intelligent Routing
"""

from fastapi import APIRouter, HTTPException, Header, Request, status
from fastapi.responses import JSONResponse
from typing import Optional
from pydantic import ValidationError
from services.ingestion.wazuh_mapper import WazuhToULFMapper
import logging
import os
import json

from services.ingestion.log_processor import LogProcessor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/alerts", tags=["Ingestion"])

# Initialize log processor (singleton)
log_processor = LogProcessor()

# API keys are loaded from environment to avoid hard-coding secrets.
def _load_valid_api_keys() -> dict:
    """
    Load API keys from the INGESTION_VALID_API_KEYS environment variable.

    Expected format (JSON object):
        {"wazuh-api-key-12345": "wazuh", "sentinelone-api-key-67890": "sentinelone"}
    """
    raw = os.getenv("INGESTION_VALID_API_KEYS")
    if not raw:
        logger.warning(
            "INGESTION_VALID_API_KEYS is not set; ingestion routes will reject all API-key auth"
        )
        return {}
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("INGESTION_VALID_API_KEYS must be a JSON object mapping keys to sources")
        # Normalize keys/values to strings
        return {str(k): str(v) for k, v in data.items()}
    except Exception as exc:
        logger.error(
            "Failed to parse INGESTION_VALID_API_KEYS; ingestion routes will reject all API-key auth",
            exc_info=exc,
        )
        return {}

VALID_API_KEYS = _load_valid_api_keys()


@router.post("/webhook/{source}", status_code=status.HTTP_202_ACCEPTED)
async def generic_webhook(
    source: str,
    request: Request,
    x_api_key: Optional[str] = Header(None)
):
    """
    Universal webhook receiver for all SIEM sources
    Intelligently routes to appropriate mapper
    
    Examples:
      POST /api/v1/alerts/webhook/wazuh
      POST /api/v1/alerts/webhook/sentinelone
      POST /api/v1/alerts/webhook/custom
    """
    
    # API key validation
    if not x_api_key or x_api_key not in VALID_API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key"
        )
    
    # Parse JSON body
    try:
        alert = await request.json()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON: {str(e)}"
        )
    
    # Process alert with intelligent routing
    try:
        ulf, warnings, summary, mapper_used = await log_processor.process_alert(
            alert, 
            source
        )
        
        # Log warnings if any
        if warnings:
            print(f"Alert {ulf.alert_id} validation warnings: {warnings}")
        
        # Push to Redis queue
        try:
            from services.ingestion.queue_manager import queue_manager
            
            # Determine if high priority (Critical/High severity)
            is_priority = ulf.severity_id in [4, 5]  # HIGH or CRITICAL
            
            # Convert ULF to dict for serialization
            ulf_dict = ulf.model_dump(mode='json')
            
            # Push to queue
            message_id = await queue_manager.push_alert(ulf_dict, priority=is_priority)
            
            logger.info(f"Alert {ulf.alert_id} queued with message ID: {message_id}")
        except Exception as queue_error:
            logger.error(f"Failed to push alert to queue: {queue_error}")
            # Continue even if queue push fails - alert is still validated
        
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={
                "status": "accepted",
                "alert_id": ulf.alert_id,
                "mapper_used": mapper_used,
                "validation": {
                    "passed": True,
                    "warnings": warnings,
                    "summary": summary
                },
                "message": "Alert queued for processing"
            }
        )
        
    except ValidationError as e:
        error_details = []
        for error in e.errors():
            error_details.append({
                "field": " -> ".join(str(x) for x in error["loc"]),
                "message": error["msg"],
                "type": error["type"]
            })
        
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "status": "validation_failed",
                "error": "Alert validation failed",
                "details": error_details
            }
        )
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal error: {str(e)}"
        )


# Keep backward compatibility - specific endpoints
#@router.post("/webhook/wazuh", status_code=status.HTTP_202_ACCEPTED)
#async def wazuh_webhook(request: Request, x_api_key: Optional[str] = Header(None)):
#    """Dedicated Wazuh webhook (calls generic webhook)"""
#    return await generic_webhook("wazuh", request, x_api_key)


#@router.post("/webhook/sentinelone", status_code=status.HTTP_202_ACCEPTED)
#async def sentinelone_webhook(request: Request, x_api_key: Optional[str] = Header(None)):
#    """Dedicated SentinelOne webhook"""
#    return await generic_webhook("sentinelone", request, x_api_key)

# COMMENTED OUT: Duplicate implementation - using generic_webhook instead
# The generic_webhook handler above already handles Wazuh alerts via LogProcessor
# Keeping this code for reference in case specific Wazuh validation is needed later

# from pydantic import ValidationError
# import traceback

# @router.post("/webhook/wazuh", status_code=status.HTTP_202_ACCEPTED)
# async def wazuh_webhook(
#     request: Request,
#     x_api_key: Optional[str] = Header(None)
# ):
#     """
#     Wazuh webhook receiver with validation
#     """
#     
#     # API key validation
#     if not x_api_key or x_api_key not in VALID_API_KEYS:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Invalid or missing API key"
#         )
#     
#     # Parse JSON body
#     try:
#         wazuh_alert = await request.json()
#     except Exception as e:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail=f"Invalid JSON: {str(e)}"
#         )
#     
#     # Validate Wazuh alert format
#     if not WazuhToULFMapper.validate_wazuh_alert(wazuh_alert):
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Invalid Wazuh alert format - missing required fields"
#         )
#     
#     # Map to ULF with validation
#     try:
#         mapper = WazuhToULFMapper()
#         ulf, warnings, summary = mapper.map_alert(wazuh_alert)
#         
#         # Log warnings if any
#         if warnings:
#             print(f"Alert {ulf.alert_id} validation warnings: {warnings}")
#         
#         # TODO: Push to Redis queue
#         # await push_to_queue(ulf)
#         
#         return JSONResponse(
#             status_code=status.HTTP_202_ACCEPTED,
#             content={
#                 "status": "accepted",
#                 "alert_id": ulf.alert_id,
#                 "validation": {
#                     "passed": True,
#                     "warnings": warnings,
#                     "summary": summary
#                 },
#                 "message": "Alert queued for processing"
#             }
#         )
#         
#     except ValidationError as e:
#         # Validation failed - return detailed error
#         error_details = []
#         for error in e.errors():
#             error_details.append({
#                 "field": " -> ".join(str(x) for x in error["loc"]),
#                 "message": error["msg"],
#                 "type": error["type"]
#             })
#         
#         return JSONResponse(
#             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
#             content={
#                 "status": "validation_failed",
#                 "error": "Alert validation failed",
#                 "details": error_details,
#                 "raw_alert": wazuh_alert
#             }
#         )
#     
#     except Exception as e:
#         # Unexpected error
#         traceback.print_exc()
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail=f"Internal error: {str(e)}"
#         )
