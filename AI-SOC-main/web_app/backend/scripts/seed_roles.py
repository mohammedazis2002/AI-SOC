#!/usr/bin/env python3
"""Seed roles collection. Run: cd backend && PYTHONPATH=. python scripts/seed_roles.py"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

backend_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_root))

from motor.motor_asyncio import AsyncIOMotorClient

from app.core.config import get_settings
from app.services.seed_roles import seed_roles_if_empty


async def main() -> None:
    settings = get_settings()
    client = AsyncIOMotorClient(settings.mongo_uri)
    db = client[settings.mongo_db_name]
    try:
        n = await seed_roles_if_empty(db)
        print(f"Inserted {n} role document(s).")
    finally:
        client.close()


if __name__ == "__main__":
    asyncio.run(main())
