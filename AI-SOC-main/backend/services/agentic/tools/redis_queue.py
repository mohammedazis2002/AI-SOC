"""
Redis Queue Manager - Manual review queue management
"""

import logging
import json
from typing import Dict, Any, Optional, List
import redis

from ..config.config import config

logger = logging.getLogger(__name__)


class RedisQueueManager:
    """
    Redis Queue Manager - Manages manual review queue.
    
    Queue: manual_review_queue
    
    Operations:
    - Push incident to queue for manual review
    - Pop next incident for analyst
    - Check queue size
    - Remove incident from queue
    """
    
    def __init__(self):
        self.client = redis.Redis(
            host=config.REDIS_HOST,
            port=config.REDIS_PORT,
            db=config.REDIS_DB,
            decode_responses=True
        )
        self.queue_name = "manual_review_queue"
        self.logger = logging.getLogger("tools.redis_queue")
    
    def push_to_review_queue(
        self,
        incident_id: str,
        priority: str,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Add incident to manual review queue.
        
        Args:
            incident_id: Incident identifier
            priority: P1, P2, P3, P4
            reason: Why manual review is needed
            metadata: Additional context
            
        Returns:
            True if successful
        """
        try:
            # Build queue item
            queue_item = {
                "incident_id": incident_id,
                "priority": priority,
                "reason": reason,
                "queued_at": str(datetime.utcnow()),
                "metadata": metadata or {}
            }
            
            # Calculate score for priority queue
            # P1 = highest priority (lowest score)
            priority_scores = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
            score = priority_scores.get(priority, 5)
            
            # Add to sorted set (priority queue)
            self.client.zadd(
                self.queue_name,
                {json.dumps(queue_item): score}
            )
            
            self.logger.info(
                f"Added incident {incident_id} to review queue "
                f"(priority: {priority}, reason: {reason})"
            )
            
            return True
        
        except redis.RedisError as e:
            self.logger.error(f"Redis error adding to queue: {e}")
            return False
    
    def pop_from_review_queue(self) -> Optional[Dict[str, Any]]:
        """
        Get next incident from review queue (highest priority).
        
        Returns:
            Queue item or None if queue is empty
        """
        try:
            # Get highest priority item (lowest score)
            items = self.client.zrange(self.queue_name, 0, 0)
            
            if not items:
                self.logger.info("Review queue is empty")
                return None
            
            # Parse item
            item_json = items[0]
            queue_item = json.loads(item_json)
            
            # Remove from queue
            self.client.zrem(self.queue_name, item_json)
            
            self.logger.info(
                f"Popped incident {queue_item['incident_id']} from review queue"
            )
            
            return queue_item
        
        except (redis.RedisError, json.JSONDecodeError) as e:
            self.logger.error(f"Error popping from queue: {e}")
            return None
    
    def get_queue_size(self) -> int:
        """
        Get number of incidents in review queue.
        
        Returns:
            Queue size
        """
        try:
            size = self.client.zcard(self.queue_name)
            return size
        except redis.RedisError as e:
            self.logger.error(f"Redis error getting queue size: {e}")
            return 0
    
    def remove_from_queue(self, incident_id: str) -> bool:
        """
        Remove specific incident from review queue.
        
        Args:
            incident_id: Incident identifier
            
        Returns:
            True if removed
        """
        try:
            # Get all items
            items = self.client.zrange(self.queue_name, 0, -1)
            
            # Find and remove matching incident
            for item_json in items:
                try:
                    queue_item = json.loads(item_json)
                    if queue_item.get("incident_id") == incident_id:
                        self.client.zrem(self.queue_name, item_json)
                        self.logger.info(f"Removed incident {incident_id} from queue")
                        return True
                except json.JSONDecodeError:
                    continue
            
            self.logger.warning(f"Incident {incident_id} not found in queue")
            return False
        
        except redis.RedisError as e:
            self.logger.error(f"Redis error removing from queue: {e}")
            return False
    
    def peek_queue(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        View items in queue without removing them.
        
        Args:
            limit: Number of items to view
            
        Returns:
            List of queue items
        """
        try:
            # Get top N items
            items = self.client.zrange(self.queue_name, 0, limit - 1)
            
            queue_items = []
            for item_json in items:
                try:
                    queue_items.append(json.loads(item_json))
                except json.JSONDecodeError:
                    continue
            
            return queue_items
        
        except redis.RedisError as e:
            self.logger.error(f"Redis error peeking queue: {e}")
            return []


# Global instance (backwards-compatible name expected by tools/__init__.py)
from datetime import datetime
redis_queue_manager = RedisQueueManager()

# Backwards-compatible alias (older agents import `redis_queue`)
redis_queue = redis_queue_manager
