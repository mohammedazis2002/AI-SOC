#!/usr/bin/env python3
"""
Copy documents from database `soar_agentic` into `soar_db` on the same MongoDB cluster.

Use when historical agentic data lived in the old default DB name while the platform uses soar_db.

Usage (from repo root, with .env loaded):

  python scripts/migrate_soar_agentic_to_soar_db.py --dry-run
  python scripts/migrate_soar_agentic_to_soar_db.py

Options:
  --include-auth   Also copy `users` and `roles` (default: skip to avoid clobbering dashboard logins)
  --source-db      Override source database name (default: soar_agentic)
  --target-db      Override target (default: MONGODB_DATABASE or soar_db)

Requires: pymongo, python-dotenv (optional)

Alternative (CLI tools):

  mongodump --db=soar_agentic --out=/tmp/soar_mig
  mongorestore --nsFrom='soar_agentic.*' --nsTo='soar_db.*' /tmp/soar_mig
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

try:
    from pymongo import MongoClient
    from pymongo.errors import OperationFailure
except ImportError:
    print("Install pymongo: pip install pymongo", file=sys.stderr)
    sys.exit(1)


def _load_dotenv() -> None:
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    repo = Path(__file__).resolve().parents[1]
    for name in (".env",):
        p = repo / name
        if p.is_file():
            load_dotenv(p)
            return


def _mongo_uri() -> str:
    uri = (os.getenv("MONGO_URI") or "").strip()
    if uri:
        return uri
    host = os.getenv("MONGODB_HOST", "localhost")
    port = os.getenv("MONGODB_PORT", "27017")
    user = os.getenv("MONGODB_USERNAME", "")
    password = os.getenv("MONGODB_PASSWORD", "")
    auth = os.getenv("MONGODB_AUTH_SOURCE", "admin")
    if user and password:
        from urllib.parse import quote_plus

        u, p = quote_plus(user), quote_plus(password)
        return f"mongodb://{u}:{p}@{host}:{port}/?authSource={auth}"
    return f"mongodb://{host}:{port}/"


def _skip_name(name: str) -> bool:
    if name.startswith("system."):
        return True
    return False


def _migrate_collection(
    *,
    src: Any,
    tgt: Any,
    dry_run: bool,
) -> tuple[int, int, int]:
    """Returns (source_count, written, errors)."""
    total = src.count_documents({})
    if dry_run:
        return total, total, 0

    written = 0
    errors = 0
    for doc in src.find({}):
        try:
            tgt.replace_one({"_id": doc["_id"]}, doc, upsert=True)
            written += 1
        except Exception as e:
            errors += 1
            print(f"    ! _id={doc.get('_id')}: {e}", file=sys.stderr)
    return total, written, errors


def main() -> int:
    _load_dotenv()

    parser = argparse.ArgumentParser(description="Migrate soar_agentic → soar_db")
    parser.add_argument("--dry-run", action="store_true", help="Count only, no writes")
    parser.add_argument("--source-db", default=os.getenv("MIGRATE_SOURCE_DB", "soar_agentic"))
    parser.add_argument(
        "--target-db",
        default=os.getenv("MONGODB_DATABASE", os.getenv("MONGO_DB", "soar_db")),
    )
    parser.add_argument(
        "--include-auth",
        action="store_true",
        help="Copy users and roles (default: skip)",
    )
    args = parser.parse_args()

    uri = _mongo_uri()
    client = MongoClient(uri, serverSelectionTimeoutMS=10_000)

    try:
        client.admin.command("ping")
    except Exception as e:
        print(f"Cannot connect to MongoDB: {e}", file=sys.stderr)
        return 1

    sdb = client[args.source_db]
    tdb = client[args.target_db]

    try:
        names = sdb.list_collection_names()
    except OperationFailure as e:
        print(f"Cannot list collections on {args.source_db!r}: {e}", file=sys.stderr)
        return 1

    skip_auth = {"users", "roles"}
    plan: list[str] = []
    for n in sorted(names):
        if _skip_name(n):
            continue
        if not args.include_auth and n in skip_auth:
            continue
        plan.append(n)

    if not plan:
        print(f"No collections to copy from {args.source_db!r} (or database empty / missing).")
        return 0

    print(f"Mongo URI host: {client.address!r}")
    print(f"Source: {args.source_db!r} → Target: {args.target_db!r}")
    if args.dry_run:
        print("DRY RUN — no writes.\n")

    grand_total = 0
    grand_written = 0
    grand_errors = 0

    for coll_name in plan:
        src = sdb[coll_name]
        tgt = tdb[coll_name]
        total, written, errs = _migrate_collection(src=src, tgt=tgt, dry_run=args.dry_run)
        grand_total += total
        grand_written += written
        grand_errors += errs
        status = f"  {coll_name}: {total} documents"
        if not args.dry_run:
            status += f" → upserted/replaced ~{written}"
        if errs:
            status += f" ({errs} bulk errors, some retried)"
        print(status)

    print(f"\nDone. Total source documents: {grand_total}")
    if not args.dry_run:
        print(f"Bulk operations applied (matched+modified+upserted tally): ~{grand_written}")
        if grand_errors:
            print(f"Remaining error count (if any): {grand_errors}")

    if args.source_db == args.target_db:
        print("\nSource and target DB names are identical — nothing to migrate.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
