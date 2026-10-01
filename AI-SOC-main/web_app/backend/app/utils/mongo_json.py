"""Convert MongoDB driver types to JSON-serializable Python values."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from bson import ObjectId


def mongo_to_json(obj: Any) -> Any:
    if obj is None:
        return None
    if isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, date):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    if isinstance(obj, dict):
        return {k: mongo_to_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [mongo_to_json(v) for v in obj]
    return obj
