import asyncio
import logging
import os
import signal
import sys
import json
from datetime import datetime
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorClient

from backend.services.ingestion.queue_manager import get_queue_manager
from backend.services.ingestion.normalisation_agent.agent import NormalisationAgent
from backend.services.agentic.config.llm_service import llm_service
from backend.services.ingestion.alert_pipeline import AlertProcessor

# Logging setup
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s | %(name)s | %(levelname)s | %(message)s"
)
logger = logging.getLogger("stream_worker")

from backend.config.settings import settings

# MongoDB connection
MONGO_URI = settings.mongodb_url
MONGO_DATABASE = settings.mongodb_database

class IngestionLLMAdapter:
    async def generate(
        self, prompt: str, max_tokens: int = 150, temperature: float = 0.0
    ) -> str:
        response = await llm_service.ainvoke(
            prompt=prompt,
            tier="secondary",
            system_message="You are a senior security data engineer. Your task is to accurately classify security events and map them to formal OCSF schemas. Output ONLY strictly valid JSON.",
        )
        return response.content


class StreamWorker:
    def __init__(self):
        self.running = False
        self.db_client = None
        self.db = None
        self.queue_manager = None
        self.agent = None
        self.processor = None
        self.consumer_name = f"worker_{os.getpid()}"

    async def startup(self):
        logger.info("Starting Stream Worker...")

        # Connect MongoDB
        self.db_client = AsyncIOMotorClient(MONGO_URI)
        self.db = self.db_client[MONGO_DATABASE]

        # Connect Redis Queue Manager
        self.queue_manager = await get_queue_manager()

        # Initialize LLM Normalisation Agent
        self.agent = NormalisationAgent(
            redis_client=self.queue_manager.redis_client,
            llm_client=IngestionLLMAdapter(),
            mongo_db=self.db,
        )

        # Initialize Alert Processor
        self.processor = AlertProcessor(
            db_client=self.db,
            redis_client=self.queue_manager.redis_client
        )
        await self.processor.start()  # Ensure indexes and correlation workers

        self.running = True
        logger.info(
            f"Stream Worker {self.consumer_name} started and ready to consume alerts."
        )

    async def shutdown(self):
        logger.info("Shutting down Stream Worker...")
        self.running = False
        if self.queue_manager:
            await self.queue_manager.disconnect()
        if self.db_client:
            self.db_client.close()
        logger.info("Shutdown complete.")

    async def _handle_failed_alert(
        self, stream_name: str, message_id: str, raw_dict: dict, error_msg: str
    ):
        """Moves a failed alert to the DLQ stream and ACKs it from the incoming stream."""
        if hasattr(self.queue_manager, "_move_to_dlq"):
            # Convert to fields format expected by _move_to_dlq
            fields = {
                "alert": json.dumps(raw_dict, default=str),
                "timestamp": datetime.utcnow().isoformat(),
            }
            await self.queue_manager._move_to_dlq(
                stream_name, message_id, fields, error_msg
            )
        else:
            logger.error(
                f"DLQ fallback not available. Alert {message_id} will be stuck."
            )

    async def run_loop(self):
        while self.running:
            try:
                # Poll Redis Streams (blocks for up to 2 seconds if empty)
                alerts = await self.queue_manager.consume_alerts(
                    consumer_name=self.consumer_name, count=10, block=2000
                )

                for alert in alerts:
                    message_id = alert["message_id"]
                    stream_name = alert["stream"]
                    raw_dict = alert["alert"]
                    alert_id = raw_dict.get("id", raw_dict.get("alert_id", "unknown"))

                    logger.info(
                        f"Processing alert {alert_id} from {stream_name} (Msg ID: {message_id})"
                    )

                    try:
                        # 1. Normalise
                        ulf = await self.agent.normalise(raw_dict)
                        if ulf:
                            logger.info(
                                f"[NORMALISED] id={ulf.get('alert_id')} "
                                f"severity={ulf.get('severity')} "
                                f"class={ulf.get('class_name')} "
                                f"technique={ulf.get('enrichments', {}).get('mitre', {}).get('technique_id')}"
                            )

                        # 2. Process (Enrich, ML, FP Detect, Correlation)
                        if ulf and ulf.get("processing_status") != "minimal_fallback":
                            await self.processor.process_alert(ulf)
                        else:
                            logger.warning(
                                f"Alert {alert_id} normalised to minimal fallback or None. Skipping pipeline."
                            )

                        # 3. Acknowledge success
                        await self.queue_manager.acknowledge_message(
                            stream_name, message_id
                        )
                        logger.info(f"Alert {alert_id} processed successfully.")

                    except Exception as e:
                        logger.error(
                            f"Failed to process alert {alert_id}: {e}", exc_info=True
                        )
                        await self._handle_failed_alert(
                            stream_name, message_id, raw_dict, str(e)
                        )

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in stream consumption loop: {e}", exc_info=True)
                await asyncio.sleep(5)  # Prevent tight loop on Redis connection failure


async def main():
    worker = StreamWorker()

    # Handle graceful shutdown
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(worker.shutdown()))

    await worker.startup()
    try:
        await worker.run_loop()
    finally:
        if worker.running:
            await worker.shutdown()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Worker interrupted by user.")
