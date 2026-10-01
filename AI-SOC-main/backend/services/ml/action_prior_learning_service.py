"""
Action Prior Learning Service
Learns remediation action preferences from analyst feedback in batch mode.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, DefaultDict, Dict, Iterable, List, Set, Tuple
import logging

from config.database import db_manager

logger = logging.getLogger(__name__)


SignalCounts = Dict[str, int]
TechniqueActionSignals = DefaultDict[str, DefaultDict[str, SignalCounts]]


class ActionPriorLearningService:
    """Incrementally updates action priors from recent analyst feedback."""

    def __init__(
        self,
        feedback_collection_name: str = "feedback_collection",
        prior_collection_name: str = "action_priors_data",
    ):
        self.feedback_collection_name = feedback_collection_name
        self.prior_collection_name = prior_collection_name

    @staticmethod
    def _to_action_set(actions: Iterable[Any] | None) -> Set[str]:
        if not actions:
            return set()
        return {str(action) for action in actions if action is not None and str(action).strip()}

    @staticmethod
    def _extract_signals(original_plan: Set[str], analyst_plan: Set[str]) -> List[Tuple[str, str]]:
        kept = [(action, "kept") for action in original_plan & analyst_plan]
        removed = [(action, "removed") for action in original_plan - analyst_plan]
        added = [(action, "added") for action in analyst_plan - original_plan]
        return kept + removed + added

    async def process_feedback_batch(self, lookback_hours: int = 6) -> Dict[str, int]:
        """
        Process non-false-positive feedback from the last N hours and update action priors.
        """
        if not db_manager._connected or db_manager.db is None:
            logger.warning("Skipping action-prior learning batch: MongoDB is not connected")
            return {
                "feedback_processed": 0,
                "techniques_updated": 0,
                "actions_updated": 0,
            }

        now = datetime.utcnow()
        threshold = now - timedelta(hours=lookback_hours)

        feedback_collection = db_manager.db[self.feedback_collection_name]
        prior_collection = db_manager.db[self.prior_collection_name]

        query = {
            "false_positive": False,
            "$or": [
                {"timestamps.feedback_submitted_at": {"$gte": threshold}},
                {"timestamp": {"$gte": threshold}},
            ],
        }
        projection = {
            "_id": 0,
            "technique_id": 1,
            "original_plan": 1,
            "analyst_plan": 1,
        }

        aggregated_signals: TechniqueActionSignals = defaultdict(
            lambda: defaultdict(lambda: {"kept": 0, "removed": 0, "added": 0})
        )
        feedback_processed = 0

        async for doc in feedback_collection.find(query, projection):
            technique_id = str(doc.get("technique_id") or "").strip()
            if not technique_id:
                continue

            original_plan = self._to_action_set(doc.get("original_plan"))
            analyst_plan = self._to_action_set(doc.get("analyst_plan"))

            for action, signal in self._extract_signals(original_plan, analyst_plan):
                aggregated_signals[technique_id][action][signal] += 1

            feedback_processed += 1

        techniques_updated = 0
        actions_updated = 0

        for technique_id, actions_map in aggregated_signals.items():
            # Ensure technique document exists.
            await prior_collection.update_one(
                {"technique_id": technique_id},
                {
                    "$setOnInsert": {
                        "technique_id": technique_id,
                        "actions": [],
                    }
                },
                upsert=True,
            )

            techniques_updated += 1

            for action, counts in actions_map.items():
                # Ensure action object exists within actions array.
                await prior_collection.update_one(
                    {
                        "technique_id": technique_id,
                        "actions.action": {"$ne": action},
                    },
                    {
                        "$push": {
                            "actions": {
                                "action": action,
                                "score": 0.0,
                                "kept_count": 0,
                                "removed_count": 0,
                                "added_count": 0,
                                "sample_size": 0,
                            }
                        }
                    },
                )

                await prior_collection.update_one(
                    {
                        "technique_id": technique_id,
                        "actions.action": action,
                    },
                    {
                        "$inc": {
                            "actions.$.kept_count": counts["kept"],
                            "actions.$.removed_count": counts["removed"],
                            "actions.$.added_count": counts["added"],
                        }
                    },
                )

                # Recompute sample_size and score for the updated action.
                await prior_collection.update_one(
                    {"technique_id": technique_id},
                    [
                        {
                            "$set": {
                                "actions": {
                                    "$map": {
                                        "input": "$actions",
                                        "as": "a",
                                        "in": {
                                            "$cond": [
                                                {"$eq": ["$$a.action", action]},
                                                {
                                                    "$let": {
                                                        "vars": {
                                                            "new_sample_size": {
                                                                "$add": [
                                                                    "$$a.kept_count",
                                                                    "$$a.removed_count",
                                                                    "$$a.added_count",
                                                                ]
                                                            }
                                                        },
                                                        "in": {
                                                            "action": "$$a.action",
                                                            "kept_count": "$$a.kept_count",
                                                            "removed_count": "$$a.removed_count",
                                                            "added_count": "$$a.added_count",
                                                            "sample_size": "$$new_sample_size",
                                                            "score": {
                                                                "$cond": [
                                                                    {"$gt": ["$$new_sample_size", 0]},
                                                                    {
                                                                        "$divide": [
                                                                            {
                                                                                "$add": [
                                                                                    "$$a.kept_count",
                                                                                    "$$a.added_count",
                                                                                ]
                                                                            },
                                                                            "$$new_sample_size",
                                                                        ]
                                                                    },
                                                                    0,
                                                                ]
                                                            },
                                                        },
                                                    }
                                                },
                                                "$$a",
                                            ]
                                        },
                                    }
                                }
                            }
                        }
                    ],
                )

                actions_updated += 1

        logger.info(
            "Action-prior learning batch complete: feedback_processed=%d, techniques_updated=%d, actions_updated=%d",
            feedback_processed,
            techniques_updated,
            actions_updated,
        )

        return {
            "feedback_processed": feedback_processed,
            "techniques_updated": techniques_updated,
            "actions_updated": actions_updated,
        }

    # Decision threshold logic removed per user request

action_prior_learning_service = ActionPriorLearningService()

