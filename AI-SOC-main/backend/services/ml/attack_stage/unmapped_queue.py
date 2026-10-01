"""
Unmapped Alert Queue System

Handles alerts that cannot be mapped to MITRE tactics after all enrichment methods fail.
No 'unknown' stages - alerts are queued for analyst review instead.
"""

import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from pymongo import MongoClient
from bson import ObjectId

logger = logging.getLogger(__name__)


class UnmappedAlertQueue:
    """
    Queue system for alerts that fail MITRE enrichment
    
    Instead of allowing 'unknown' stages, alerts without MITRE data are:
    1. Queued for analyst review
    2. Tracked with enrichment attempt history
    3. Prioritized based on alert characteristics
    4. Made available via API for manual mapping
    """
    
    def __init__(self, mongo_client: MongoClient, database: str = 'soar'):
        """
        Initialize unmapped alert queue
        
        Args:
            mongo_client: MongoDB client instance
            database: Database name
        """
        self.db = mongo_client[database]
        self.queue = self.db['unmapped_alerts_queue']
        
        # Create indexes for efficient querying
        self._create_indexes()
    
    def _create_indexes(self):
        """Create database indexes for queue performance"""
        try:
            self.queue.create_index([('status', 1), ('queued_at', -1)])
            self.queue.create_index('alert_id', unique=True)
            self.queue.create_index('priority')
            logger.info("Created indexes for unmapped_alerts_queue")
        except Exception as e:
            logger.error(f"Failed to create indexes: {e}")
    
    def add_to_queue(
        self, 
        alert: Dict[str, Any], 
        enrichment_attempts: Dict[str, bool], 
        reason: str = "All MITRE enrichment methods failed"
    ) -> str:
        """
        Add an alert to the unmapped queue
        
        Args:
            alert: Full alert object
            enrichment_attempts:  Track which enrichment methods were attempted
            reason: Human-readable reason for queuing
        
        Returns:
            Queue entry ID
        """
        
        # Determine priority based on alert characteristics
        priority = self._calculate_priority(alert)
        
        queue_entry = {
            'alert_id': alert.get('alert_id'),
            'alert': alert,
            'queued_at': datetime.utcnow(),
            'status': 'pending_review',  # pending_review | reviewed | rejected
            'reason': reason,
            'priority': priority,  # critical | high | medium | low
            'enrichment_attempts': enrichment_attempts,
            'reviewed_at': None,
            'reviewed_by': None,
            'analyst_provided_mitre': None,
            'notes': []
        }
        
        try:
            result = self.queue.insert_one(queue_entry)
            logger.info(
                f"Alert {alert.get('alert_id')} added to unmapped queue "
                f"with priority {priority}"
            )
            return str(result.inserted_id)
        
        except Exception as e:
            logger.error(f"Failed to add alert to queue: {e}")
            raise
    
    def _calculate_priority(self, alert: Dict[str, Any]) -> str:
        """
        Calculate priority for unmapped alert
        
        Higher-severity alerts and those affecting critical assets get higher priority
        """
        
        severity = alert.get('severity', 'medium').lower()
        asset_criticality = alert.get('device', {}).get('criticality', 'medium').lower()
        
        # Critical if alert or asset is critical
        if severity == 'critical' or asset_criticality == 'critical':
            return 'critical'
        
        # High if either severity or asset is high
        elif severity == 'high' or asset_criticality == 'high':
            return 'high'
        
        # Medium if moderate severity
        elif severity == 'medium':
            return 'medium'
        
        # Low for everything else
        else:
            return 'low'
    
    def get_pending_alerts(
        self, 
        priority: Optional[str] = None, 
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get pending unmapped alerts for analyst review
        
        Args:
            priority: Filter by priority (critical|high|medium|low)
            limit: Maximum number of alerts to return
        
        Returns:
            List of pending alerts
        """
        
        query = {'status': 'pending_review'}
        if priority:
            query['priority'] = priority
        
        # Sort by priority (critical first) then by queued time
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        
        results = list(self.queue.find(query).limit(limit))
        
        # Sort by custom priority order
        results.sort(
            key=lambda x: (
                priority_order.get(x.get('priority', 'low'), 3),
                x.get('queued_at', datetime.min)
            )
        )
        
        # Convert ObjectId to string for JSON serialization
        for result in results:
            result['_id'] = str(result['_id'])
        
        return results
    
    def submit_review(
        self, 
        queue_id: str, 
        analyst_mitre: Dict[str, Any], 
        analyst_id: str,
        notes: Optional[str] = None
    ) -> bool:
        """
        Submit analyst review with MITRE mapping
        
        Args:
            queue_id: Queue entry ID
            analyst_mitre: MITRE mapping provided by analyst
            analyst_id: ID of reviewing analyst
            notes: Optional notes from analyst
        
        Returns:
            True if successful
        """
        
        update = {
            'status': 'reviewed',
            'reviewed_at': datetime.utcnow(),
            'reviewed_by': analyst_id,
            'analyst_provided_mitre': analyst_mitre
        }
        
        if notes:
            update['notes'] = {'analyst': analyst_id, 'note': notes, 'timestamp': datetime.utcnow()}
        
        try:
            result = self.queue.update_one(
                {'_id': ObjectId(queue_id)},
                {'$set': update}
            )
            
            if result.modified_count > 0:
                logger.info(f"Queue entry {queue_id} reviewed by analyst {analyst_id}")
                return True
            else:
                logger.warning(f"Queue entry {queue_id} not found")
                return False
        
        except Exception as e:
            logger.error(f"Failed to submit review: {e}")
            return False
    
    def reject_alert(
        self, 
        queue_id: str, 
        analyst_id: str, 
        reason: str
    ) -> bool:
        """
        Reject alert as not attack-related
        
        Args:
            queue_id: Queue entry ID
            analyst_id: ID of reviewing analyst
            reason: Reason for rejection
        
        Returns:
            True if successful
        """
        
        update = {
            'status': 'rejected',
            'reviewed_at': datetime.utcnow(),
            'reviewed_by': analyst_id,
            'rejection_reason': reason
        }
        
        try:
            result = self.queue.update_one(
                {'_id': ObjectId(queue_id)},
                {'$set': update}
            )
            
            if result.modified_count > 0:
                logger.info(f"Queue entry {queue_id} rejected by analyst {analyst_id}")
                return True
            else:
                return False
        
        except Exception as e:
            logger.error(f"Failed to reject alert: {e}")
            return False
    
    def get_queue_stats(self) -> Dict[str, Any]:
        """
        Get queue statistics
        
        Returns:
            Statistics about the unmapped alert queue
        """
        
        total_pending = self.queue.count_documents({'status': 'pending_review'})
        total_reviewed = self.queue.count_documents({'status': 'reviewed'})
        total_rejected = self.queue.count_documents({'status': 'rejected'})
        
        pending_by_priority = {
            'critical': self.queue.count_documents({'status': 'pending_review', 'priority': 'critical'}),
            'high': self.queue.count_documents({'status': 'pending_review', 'priority': 'high'}),
            'medium': self.queue.count_documents({'status': 'pending_review', 'priority': 'medium'}),
            'low': self.queue.count_documents({'status': 'pending_review', 'priority': 'low'})
        }
        
        # Get oldest pending alert
        oldest = self.queue.find_one(
            {'status': 'pending_review'},
            sort=[('queued_at', 1)]
        )
        
        oldest_age_hours = None
        if oldest:
            age = datetime.utcnow() - oldest.get('queued_at', datetime.utcnow())
            oldest_age_hours = age.total_seconds() / 3600
        
        return {
            'total_pending': total_pending,
            'total_reviewed': total_reviewed,
            'total_rejected': total_rejected,
            'pending_by_priority': pending_by_priority,
            'oldest_pending_age_hours': oldest_age_hours
        }
    
    def get_reviewed_mappings(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get analyst-reviewed mappings for training/improvement
        
        Can be used to:
        1. Train ML models for automatic enrichment
        2. Build pattern libraries
        3. Improve enrichment rules
        
        Args:
            limit: Maximum number of mappings to return
        
        Returns:
            List of reviewed mappings
        """
        
        results = list(self.queue.find(
            {'status': 'reviewed'},
            {
                'alert.class_name': 1,
                'alert.severity': 1,
                'alert.message': 1,
                'analyst_provided_mitre': 1,
                'reviewed_at': 1,
                'reviewed_by': 1
            }
        ).limit(limit))
        
        for result in results:
            result['_id'] = str(result['_id'])
        
        return results
