"""
Redis Queue Manager for SOAR Platform
Handles Redis Streams for alert processing pipeline
"""

import os
import redis.asyncio as redis
from typing import Dict, Any, Optional, List
import json
import logging
from datetime import datetime
from backend.config.settings import settings

logger = logging.getLogger(__name__)


class QueueManager:
    """Redis Streams queue manager for alert processing"""
    
    def __init__(self):
        self.redis_client: Optional[redis.Redis] = None
        self._connected = False
        self._dedupe_ttl_seconds = int(os.getenv("REDIS_INGEST_DEDUPE_TTL_SECONDS", "86400"))
        
        # Stream names
        self.stream_incoming = settings.redis_stream_incoming
        self.stream_dlq = settings.redis_stream_dlq
        self.stream_priority = settings.redis_stream_priority
        self.consumer_group = settings.redis_consumer_group
    
    async def connect(self):
        """Establish connection to Redis"""
        try:
            logger.info(f"Connecting to Redis at {settings.redis_host}:{settings.redis_port}")
            
            self.redis_client = redis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=5,
                socket_keepalive=True
            )
            
            # Test connection
            await self.redis_client.ping()
            
            # Create consumer groups if they don't exist
            await self._create_consumer_groups()
            
            self._connected = True
            logger.info("✅ Redis connected successfully")
            
        except Exception as e:
            logger.error(f"❌ Redis connection failed: {e}")
            raise
    
    async def disconnect(self):
        """Close Redis connection"""
        if self.redis_client:
            await self.redis_client.close()
            self._connected = False
            logger.info("Redis connection closed")
    
    async def _create_consumer_groups(self):
        """Create consumer groups for streams"""
        streams = [self.stream_incoming, self.stream_priority]
        
        for stream in streams:
            try:
                # Try to create consumer group
                await self.redis_client.xgroup_create(
                    name=stream,
                    groupname=self.consumer_group,
                    id='0',
                    mkstream=True
                )
                logger.info(f"Created consumer group '{self.consumer_group}' for stream '{stream}'")
            except redis.ResponseError as e:
                if "BUSYGROUP" in str(e):
                    # Group already exists
                    logger.debug(f"Consumer group '{self.consumer_group}' already exists for '{stream}'")
                else:
                    raise
    
    async def push_alert(
        self,
        ulf_dict: Dict[str, Any],
        priority: bool = False
    ) -> str:
        """
        Push alert to Redis stream
        
        Args:
            ulf_dict: ULF alert dictionary
            priority: If True, push to priority queue
            
        Returns:
            Message ID
        """
        try:
            # Best-effort idempotency guard:
            # Many SIEM senders retry webhooks/mTLS POSTs (at-least-once delivery).
            # Use source_alert_id/id when present to avoid duplicate stream entries.
            # If we can't derive a stable key, we fall back to always enqueue.
            dedupe_key: str | None = None
            for k in ("source_alert_id", "id", "alert_id"):
                v = ulf_dict.get(k)
                if v is not None and str(v).strip():
                    dedupe_key = f"dedupe:alerts_incoming:{k}:{str(v).strip()}"
                    break
            if dedupe_key and self._dedupe_ttl_seconds > 0:
                ok = await self.redis_client.set(
                    dedupe_key,
                    "1",
                    nx=True,
                    ex=self._dedupe_ttl_seconds,
                )
                if not ok:
                    logger.warning(
                        "Deduped alert push — not written to Redis stream (key=%s, ttl=%ss)",
                        dedupe_key,
                        self._dedupe_ttl_seconds,
                    )
                    return "deduped"

            # Serialize ULF to JSON
            alert_json = json.dumps(ulf_dict, default=str)
            
            # Choose stream based on priority
            stream = self.stream_priority if priority else self.stream_incoming
            
            # Push to stream
            message_id = await self.redis_client.xadd(
                name=stream,
                fields={
                    "alert": alert_json,
                    "timestamp": datetime.utcnow().isoformat(),
                    "alert_id": ulf_dict.get("alert_id", "unknown")
                }
            )
            
            logger.info(f"Alert {ulf_dict.get('alert_id')} pushed to {stream} (ID: {message_id})")
            return message_id
            
        except Exception as e:
            logger.error(f"Failed to push alert to queue: {e}")
            raise
    
    def _parse_stream_fields(self, fields: Any) -> Dict[str, Any]:
        """Normalize XREADGROUP/XAUTOCLAIM field payload to a string-keyed dict."""
        if isinstance(fields, dict):
            return fields
        if isinstance(fields, (list, tuple)) and fields:
            return dict(zip(fields[0::2], fields[1::2]))
        return {}

    async def _autoclaim_idle(
        self,
        consumer_name: str,
        count: int,
    ) -> List[Dict[str, Any]]:
        """
        Claim pending entries idle longer than min_idle (stale deliveries after worker crash).
        """
        if count <= 0:
            return []
        min_idle = int(os.getenv("REDIS_STREAM_CLAIM_MIN_IDLE_MS", "60000"))
        alerts: List[Dict[str, Any]] = []
        for stream in (self.stream_priority, self.stream_incoming):
            if len(alerts) >= count:
                break
            try:
                result = await self.redis_client.xautoclaim(
                    name=stream,
                    groupname=self.consumer_group,
                    consumername=consumer_name,
                    min_idle_time=min_idle,
                    start_id="0-0",
                    count=count - len(alerts),
                )
            except redis.ResponseError as e:
                if "NOGROUP" in str(e) or "no such key" in str(e).lower():
                    continue
                raise
            if not result:
                continue
            # redis-py: [next_id, messages, deleted_ids?]
            claimed = result[1] if isinstance(result, (list, tuple)) and len(result) > 1 else []
            if not claimed:
                continue
            for item in claimed:
                if not isinstance(item, (list, tuple)) or len(item) < 2:
                    continue
                message_id, raw_fields = item[0], item[1]
                fields = self._parse_stream_fields(raw_fields)
                try:
                    alert_data = json.loads(fields["alert"])
                    alerts.append(
                        {
                            "message_id": message_id,
                            "stream": stream,
                            "alert": alert_data,
                            "timestamp": fields.get("timestamp"),
                        }
                    )
                except (KeyError, TypeError, json.JSONDecodeError) as e:
                    logger.error(
                        "Failed to parse claimed alert from message %s: %s",
                        message_id,
                        e,
                    )
                    await self._move_to_dlq(stream, message_id, fields, str(e))
        return alerts

    async def consume_alerts(
        self,
        consumer_name: str,
        count: int = 10,
        block: int = 1000
    ) -> List[Dict[str, Any]]:
        """
        Consume alerts from stream
        
        Args:
            consumer_name: Unique consumer identifier
            count: Number of messages to read
            block: Block time in milliseconds
            
        Returns:
            List of alerts
        """
        try:
            alerts: List[Dict[str, Any]] = []

            # Recover stale pending deliveries (e.g. worker died after XREADGROUP, before XACK).
            if os.getenv("REDIS_STREAM_AUTOCLAIM", "1").lower() in ("1", "true", "yes"):
                try:
                    alerts.extend(await self._autoclaim_idle(consumer_name, count))
                except Exception as e:
                    logger.warning(
                        "XAUTOCLAIM failed (continuing with XREADGROUP only): %s",
                        e,
                    )

            remaining = max(0, count - len(alerts))
            if remaining == 0:
                return alerts

            # Read from both streams
            streams = {
                self.stream_priority: '>',  # Priority first
                self.stream_incoming: '>'
            }
            
            messages = await self.redis_client.xreadgroup(
                groupname=self.consumer_group,
                consumername=consumer_name,
                streams=streams,
                count=remaining,
                block=block
            )
            
            for stream_name, stream_messages in messages:
                for message_id, fields in stream_messages:
                    try:
                        fields_d = self._parse_stream_fields(fields)
                        alert_data = json.loads(fields_d["alert"])
                        alerts.append({
                            'message_id': message_id,
                            'stream': stream_name,
                            'alert': alert_data,
                            'timestamp': fields_d.get('timestamp')
                        })
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse alert from message {message_id}: {e}")
                        # Move to DLQ
                        await self._move_to_dlq(
                            stream_name,
                            message_id,
                            self._parse_stream_fields(fields),
                            str(e),
                        )
            
            return alerts
            
        except Exception as e:
            logger.error(f"Failed to consume alerts: {e}")
            return []
    
    async def acknowledge_message(
        self,
        stream: str,
        message_id: str
    ):
        """Acknowledge message processing"""
        try:
            await self.redis_client.xack(
                stream,
                self.consumer_group,
                message_id
            )
            logger.debug(f"Acknowledged message {message_id} from {stream}")
        except Exception as e:
            logger.error(f"Failed to acknowledge message {message_id}: {e}")
    
    async def _move_to_dlq(
        self,
        original_stream: str,
        message_id: str,
        fields: Dict[str, Any],
        error: str
    ):
        """Move failed message to Dead Letter Queue"""
        try:
            # Add error info
            dlq_fields = {
                **fields,
                "original_stream": original_stream,
                "original_message_id": message_id,
                "error": error,
                "dlq_timestamp": datetime.utcnow().isoformat()
            }
            
            # Push to DLQ
            await self.redis_client.xadd(
                name=self.stream_dlq,
                fields=dlq_fields
            )
            
            # Acknowledge original message
            await self.acknowledge_message(original_stream, message_id)
            
            logger.warning(f"Moved message {message_id} to DLQ: {error}")
            
        except Exception as e:
            logger.error(f"Failed to move message to DLQ: {e}")
    
    async def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics"""
        try:
            stats = {}
            
            for stream in [self.stream_incoming, self.stream_priority, self.stream_dlq]:
                try:
                    # Get stream length
                    length = await self.redis_client.xlen(stream)
                    
                    # Get pending messages
                    pending_info = await self.redis_client.xpending(
                        stream,
                        self.consumer_group
                    )
                    
                    stats[stream] = {
                        "length": length,
                        "pending": pending_info['pending'] if pending_info else 0
                    }
                except redis.ResponseError:
                    # Stream doesn't exist yet
                    stats[stream] = {"length": 0, "pending": 0}
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get queue stats: {e}")
            return {}
    
    async def health_check(self) -> Dict[str, Any]:
        """Check Redis health"""
        try:
            if not self._connected:
                return {"status": "disconnected"}
            
            # Ping Redis
            await self.redis_client.ping()
            
            # Get queue stats
            stats = await self.get_queue_stats()
            
            return {
                "status": "healthy",
                "queues": stats
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }


# Global queue manager instance
queue_manager = QueueManager()


# Dependency for FastAPI
async def get_queue_manager() -> QueueManager:
    """FastAPI dependency to get queue manager"""
    if not queue_manager._connected:
        await queue_manager.connect()
    return queue_manager
