"""
Human-in-the-Loop Review System
AI-mapped alerts are held for analyst approval before final storage
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum

from schemas.ulf_schema import UnifiedLogFormat


class ReviewDecision(str, Enum):
    """Possible review decisions"""
    APPROVED = "approved"
    REJECTED = "rejected"
    MODIFIED = "modified"
    ESCALATED = "escalated"


class ReviewStatus(str, Enum):
    """Review workflow statuses"""
    PENDING_REVIEW = "pending_review"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    MODIFIED = "modified"


class HumanReviewSystem:
    """
    Manages human-in-the-loop review for AI-mapped alerts
    """
    
    def __init__(self, mongodb_client, review_threshold: float = 0.7):
        """
        Args:
            mongodb_client: MongoDB client for storing review queue
            review_threshold: Confidence below this requires human review
        """
        self.db = mongodb_client
        self.review_threshold = review_threshold
    
    async def needs_review(self, ulf: UnifiedLogFormat, confidence: float) -> bool:
        """
        Determine if an alert needs human review
        
        Criteria:
        1. AI confidence < threshold
        2. Mapped using AI (not rule-based)
        3. Critical/High severity (extra validation)
        4. Mapping failed (fallback was used)
        """
        
        # Always review if confidence is low
        if confidence < self.review_threshold:
            return True
        
        # Always review AI-mapped alerts (at least initially)
        if ulf.processing_status.startswith("ai_mapped"):
            return True
        
        # Always review if mapping failed
        if ulf.processing_status == "mapping_failed_requires_manual_review":
            return True
        
        # Review critical alerts for extra validation
        if ulf.severity in ["Critical", "High"] and "ai" in ulf.unmapped.get("mapping_method", ""):
            return True
        
        return False
    
    async def submit_for_review(
        self, 
        ulf: UnifiedLogFormat, 
        confidence: float,
        reason: str = "AI mapping requires validation"
    ) -> str:
        """
        Submit alert to review queue
        
        Returns:
            Review ID
        """
        
        review_doc = {
            "review_id": f"REV-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{ulf.alert_id[-8:]}",
            "alert_id": ulf.alert_id,
            "ulf_data": ulf.model_dump(),
            "ai_confidence": confidence,
            "review_status": ReviewStatus.PENDING_REVIEW,
            "reason": reason,
            "submitted_at": datetime.utcnow(),
            "assigned_to": None,
            "reviewed_at": None,
            "reviewer_notes": None,
            "decision": None,
            "modified_fields": {}
        }
        
        # Store in review queue
        await self.db.review_queue.insert_one(review_doc)
        
        return review_doc["review_id"]
    
    async def get_pending_reviews(
        self, 
        analyst_id: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get alerts pending review
        
        Args:
            analyst_id: Filter by assigned analyst (None = unassigned)
            limit: Max number to return
        """
        
        query = {"review_status": ReviewStatus.PENDING_REVIEW}
        if analyst_id:
            query["assigned_to"] = analyst_id
        
        cursor = self.db.review_queue.find(query).sort("submitted_at", 1).limit(limit)
        reviews = await cursor.to_list(length=limit)
        
        return reviews
    
    async def claim_review(self, review_id: str, analyst_id: str) -> bool:
        """
        Analyst claims a review item
        """
        
        result = await self.db.review_queue.update_one(
            {
                "review_id": review_id,
                "review_status": ReviewStatus.PENDING_REVIEW
            },
            {
                "$set": {
                    "assigned_to": analyst_id,
                    "review_status": ReviewStatus.IN_REVIEW,
                    "claimed_at": datetime.utcnow()
                }
            }
        )
        
        return result.modified_count > 0
    
    async def approve_alert(
        self, 
        review_id: str, 
        analyst_id: str,
        notes: Optional[str] = None
    ) -> UnifiedLogFormat:
        """
        Analyst approves the AI-mapped alert as-is
        Returns the approved ULF for final storage
        """
        
        review = await self.db.review_queue.find_one({"review_id": review_id})
        if not review:
            raise ValueError(f"Review {review_id} not found")
        
        # Update review record
        await self.db.review_queue.update_one(
            {"review_id": review_id},
            {
                "$set": {
                    "review_status": ReviewStatus.APPROVED,
                    "decision": ReviewDecision.APPROVED,
                    "reviewed_at": datetime.utcnow(),
                    "reviewed_by": analyst_id,
                    "reviewer_notes": notes
                }
            }
        )
        
        # Update ULF processing status
        ulf = UnifiedLogFormat(**review["ulf_data"])
        ulf.processing_status = "approved_by_analyst"
        ulf.unmapped["reviewed_by"] = analyst_id
        ulf.unmapped["reviewed_at"] = datetime.utcnow().isoformat()
        
        return ulf
    
    async def reject_alert(
        self, 
        review_id: str, 
        analyst_id: str,
        reason: str
    ):
        """
        Analyst rejects the AI-mapped alert (false positive, bad mapping)
        """
        
        await self.db.review_queue.update_one(
            {"review_id": review_id},
            {
                "$set": {
                    "review_status": ReviewStatus.REJECTED,
                    "decision": ReviewDecision.REJECTED,
                    "reviewed_at": datetime.utcnow(),
                    "reviewed_by": analyst_id,
                    "reviewer_notes": reason
                }
            }
        )
        
        # Store rejection for ML retraining feedback
        review = await self.db.review_queue.find_one({"review_id": review_id})
        await self.db.feedback_data.insert_one({
            "alert_id": review["alert_id"],
            "feedback_type": "rejection",
            "original_mapping": review["ulf_data"],
            "reason": reason,
            "analyst_id": analyst_id,
            "timestamp": datetime.utcnow()
        })
    
    async def modify_alert(
        self, 
        review_id: str, 
        analyst_id: str,
        modifications: Dict[str, Any],
        notes: str
    ) -> UnifiedLogFormat:
        """
        Analyst modifies fields before approval
        
        Args:
            modifications: Dict of field paths to new values
                Example: {"severity": "High", "finding.title": "Corrected title"}
        """
        
        review = await self.db.review_queue.find_one({"review_id": review_id})
        if not review:
            raise ValueError(f"Review {review_id} not found")
        
        # Update review record
        await self.db.review_queue.update_one(
            {"review_id": review_id},
            {
                "$set": {
                    "review_status": ReviewStatus.MODIFIED,
                    "decision": ReviewDecision.MODIFIED,
                    "reviewed_at": datetime.utcnow(),
                    "reviewed_by": analyst_id,
                    "reviewer_notes": notes,
                    "modified_fields": modifications
                }
            }
        )
        
        # Apply modifications to ULF
        ulf = UnifiedLogFormat(**review["ulf_data"])
        
        for field_path, new_value in modifications.items():
            # Handle nested fields (e.g., "finding.title")
            parts = field_path.split(".")
            obj = ulf
            for part in parts[:-1]:
                obj = getattr(obj, part)
            setattr(obj, parts[-1], new_value)
        
        # Update processing status
        ulf.processing_status = "modified_by_analyst"
        ulf.unmapped["reviewed_by"] = analyst_id
        ulf.unmapped["reviewed_at"] = datetime.utcnow().isoformat()
        ulf.unmapped["analyst_modifications"] = modifications
        
        # Store modification for ML retraining feedback
        await self.db.feedback_data.insert_one({
            "alert_id": review["alert_id"],
            "feedback_type": "modification",
            "original_mapping": review["ulf_data"],
            "modifications": modifications,
            "analyst_id": analyst_id,
            "timestamp": datetime.utcnow()
        })
        
        return ulf
    
    async def ask_ai_to_revise(
        self, 
        review_id: str,
        analyst_feedback: str,
        ai_mapper
    ) -> UnifiedLogFormat:
        """
        Send feedback to AI to try again
        Analyst provides guidance, AI remaps the log
        """
        
        review = await self.db.review_queue.find_one({"review_id": review_id})
        if not review:
            raise ValueError(f"Review {review_id} not found")
        
        # Get original raw log
        original_ulf = UnifiedLogFormat(**review["ulf_data"])
        raw_log = original_ulf.raw_data
        
        # Enhanced prompt with analyst feedback
        revised_prompt = f"""Raw Log:
{raw_log}

ANALYST FEEDBACK:
{analyst_feedback}

Please re-analyze this log considering the analyst's feedback.
Return ONLY the JSON object."""
        
        # Call AI with feedback
        revised_ulf, confidence = await ai_mapper.map_log(
            raw_log, 
            original_ulf.siem_source
        )
        
        # Update review with new version
        await self.db.review_queue.update_one(
            {"review_id": review_id},
            {
                "$set": {
                    "ulf_data": revised_ulf.model_dump(),
                    "ai_confidence": confidence,
                    "revision_count": review.get("revision_count", 0) + 1,
                    "last_revision": datetime.utcnow(),
                    "analyst_feedback": analyst_feedback
                }
            }
        )
        
        return revised_ulf
