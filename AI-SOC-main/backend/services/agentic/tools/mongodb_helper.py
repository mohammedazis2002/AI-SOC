"""
MongoDB Helper - Database operations for incidents and audit logs
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from pymongo import MongoClient
from pymongo.errors import PyMongoError

from ..config.config import config

logger = logging.getLogger(__name__)


class MongoDBHelper:
    """
    MongoDB Helper - CRUD operations for incidents and audit logs.
    
    Collections:
    - incidents: Full incident data with all enrichments
    - audit_logs: Complete audit trail (includes agent metrics)
    - cold_storage: 90-day compliance retention
    """
    
    def __init__(self):
        self.client = MongoClient(config.MONGO_URI)
        self.db = self.client[config.MONGO_DB]
        self.collections = config.MONGO_COLLECTIONS
        self.logger = logging.getLogger("tools.mongodb")
    
    def save_incident(self, incident: Dict[str, Any]) -> bool:
        """
        Save or update incident.
        
        Args:
            incident: Incident document
            
        Returns:
            True if successful
        """
        try:
            incident_id = incident.get("incident_id")
            
            if not incident_id:
                self.logger.error("Incident missing incident_id")
                return False
            
            # Add metadata
            incident["updated_at"] = datetime.utcnow()
            if "created_at" not in incident:
                incident["created_at"] = datetime.utcnow()
            
            # Upsert (update if exists, insert if new)
            result = self.db[self.collections["incidents"]].update_one(
                {"incident_id": incident_id},
                {"$set": incident},
                upsert=True
            )
            
            self.logger.info(
                f"Saved incident {incident_id} "
                f"(matched: {result.matched_count}, modified: {result.modified_count})"
            )
            
            return True
        
        except PyMongoError as e:
            self.logger.error(f"MongoDB error saving incident: {e}")
            return False
    
    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve incident by ID.
        
        Args:
            incident_id: Incident identifier
            
        Returns:
            Incident document or None
        """
        try:
            incident = self.db[self.collections["incidents"]].find_one(
                {"incident_id": incident_id},
                {"_id": 0}  # Exclude MongoDB _id field
            )
            
            if incident:
                self.logger.info(f"Retrieved incident {incident_id}")
            else:
                self.logger.warning(f"Incident {incident_id} not found")
            
            return incident
        
        except PyMongoError as e:
            self.logger.error(f"MongoDB error retrieving incident: {e}")
            return None
    
    def save_audit_log(self, audit_log: Dict[str, Any]) -> bool:
        """
        Save audit log entry.
        
        Args:
            audit_log: Audit log document
            
        Returns:
            True if successful
        """
        try:
            # Add timestamp if not present
            if "timestamp" not in audit_log:
                audit_log["timestamp"] = datetime.utcnow()
            
            # Insert audit log
            result = self.db[self.collections["audit_logs"]].insert_one(audit_log)
            
            self.logger.info(f"Saved audit log for incident {audit_log.get('incident_id')}")
            
            return True
        
        except PyMongoError as e:
            self.logger.error(f"MongoDB error saving audit log: {e}")
            return False
    
    def get_audit_logs(
        self,
        incident_id: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Retrieve audit logs for an incident.
        
        Args:
            incident_id: Incident identifier
            limit: Maximum number of logs
            
        Returns:
            List of audit log entries
        """
        try:
            logs = list(
                self.db[self.collections["audit_logs"]]
                .find({"incident_id": incident_id}, {"_id": 0})
                .sort("timestamp", -1)
                .limit(limit)
            )
            
            self.logger.info(f"Retrieved {len(logs)} audit logs for {incident_id}")
            
            return logs
        
        except PyMongoError as e:
            self.logger.error(f"MongoDB error retrieving audit logs: {e}")
            return []
    
    def archive_incident(self, incident_id: str) -> bool:
        """
        Move incident to cold storage (90-day retention).
        
        Args:
            incident_id: Incident identifier
            
        Returns:
            True if successful
        """
        try:
            # Get incident
            incident = self.get_incident(incident_id)
            
            if not incident:
                self.logger.warning(f"Cannot archive non-existent incident {incident_id}")
                return False
            
            # Add archive metadata
            incident["archived_at"] = datetime.utcnow()
            incident["status"] = "archived"
            
            # Insert into cold storage
            self.db[self.collections["cold_storage"]].insert_one(incident)
            
            # Optional: Remove from active incidents
            # self.db[self.collections["incidents"]].delete_one({"incident_id": incident_id})
            
            self.logger.info(f"Archived incident {incident_id} to cold storage")
            
            return True
        
        except PyMongoError as e:
            self.logger.error(f"MongoDB error archiving incident: {e}")
            return False


# Global instance
mongodb_helper = MongoDBHelper()
