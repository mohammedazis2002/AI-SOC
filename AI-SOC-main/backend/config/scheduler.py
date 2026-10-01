"""
APScheduler manager for background jobs.
"""

import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler

logger = logging.getLogger(__name__)


class SchedulerManager:
    """Wrapper around AsyncIOScheduler with safe start/stop operations."""

    def __init__(self):
        self.scheduler = AsyncIOScheduler(timezone="UTC")

    def add_interval_job(self, func, hours: int, job_id: str):
        """Register or replace an interval job."""
        self.scheduler.add_job(
            func,
            "interval",
            hours=hours,
            id=job_id,
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        logger.info("Scheduled job '%s' every %d hours", job_id, hours)

    def start(self):
        """Start scheduler if not already running."""
        if not self.scheduler.running:
            self.scheduler.start()
            logger.info("AsyncIOScheduler started")

    def shutdown(self):
        """Stop scheduler if running."""
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)
            logger.info("AsyncIOScheduler stopped")


scheduler_manager = SchedulerManager()
