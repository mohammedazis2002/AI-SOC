from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class WazuhRule(BaseModel):
    """Wazuh rule information"""

    level: int
    description: str
    id: str
    firedtimes: Optional[int] = None
    mail: Optional[bool] = None
    groups: Optional[List[str]] = None
    pci_dss: Optional[List[str]] = None
    gdpr: Optional[List[str]] = None


class WazuhAgent(BaseModel):
    """Wazuh agent information"""

    id: str
    name: str
    ip: Optional[str] = None


class WazuhManager(BaseModel):
    """Wazuh manager information"""

    name: str


class WazuhDecoder(BaseModel):
    """Wazuh decoder information"""

    name: str


class WazuhAlert(BaseModel):
    """Schema for Wazuh alert payloads"""

    timestamp: str = Field(..., description="Alert timestamp")
    rule: WazuhRule = Field(..., description="Rule information")
    agent: WazuhAgent = Field(..., description="Agent information")
    manager: Optional[WazuhManager] = Field(
        None, description="Manager information (optional for some forwarders)"
    )
    id: str = Field(..., description="Alert ID")
    full_log: Optional[str] = Field(
        None, description="Full log message (optional if original event has no raw line)"
    )
    decoder: Optional[WazuhDecoder] = Field(None, description="Decoder used")
    data: Optional[Dict[str, Any]] = Field(None, description="Additional alert data")
    location: Optional[str] = Field(None, description="Log source location")

    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "2026-02-04T21:04:59.528+0000",
                "rule": {
                    "level": 7,
                    "description": "Host-based anomaly detection event",
                    "id": "510",
                },
                "agent": {"id": "000", "name": "ubuntu"},
                "manager": {"name": "ubuntu"},
                "id": "1770239099.254205",
                "full_log": "Trojaned version of file detected.",
            }
        }


class WazuhAlertResponse(BaseModel):
    """Response after processing Wazuh alert"""

    status: str = Field(..., description="Processing status")
    message: str = Field(..., description="Status message")
    alert_id: str = Field(..., description="Processed alert ID")
    processed_at: datetime = Field(default_factory=datetime.utcnow)
