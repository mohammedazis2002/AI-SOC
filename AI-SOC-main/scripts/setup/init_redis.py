#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Redis Initialization Script
Sets up Redis Streams and initial cache structure
"""

import os
import sys
import redis
from dotenv import load_dotenv

load_dotenv()

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "change_this_redis_password")
REDIS_DB = int(os.getenv("REDIS_DB", 0))


def init_redis():
    """Initialize Redis with streams and consumer groups"""
    
    # Connect to Redis
    r = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASSWORD,
        db=REDIS_DB,
        decode_responses=True
    )
    
    print(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
    
    # Test connection
    try:
        r.ping()
        print("✓ Redis connection successful")
    except redis.ConnectionError as e:
        print(f"✗ Failed to connect to Redis: {e}")
        sys.exit(1)
    
    # Create Redis Streams
    streams = [
        "alerts:incoming",
        "alerts:dlq",
        "alerts:priority"
    ]
    
    print("\nCreating Redis Streams...")
    for stream in streams:
        if not r.exists(stream):
            r.xadd(stream, {"init": "true"})
            stream_info = r.xinfo_stream(stream)
            first_id = stream_info['first-entry'][0]
            r.xdel(stream, first_id)
            print(f"✓ Created stream: {stream}")
        else:
            print(f"ℹ Stream already exists: {stream}")
    
    # Create consumer groups
    consumer_group = os.getenv("REDIS_CONSUMER_GROUP", "soar-consumers")
    
    print(f"\nCreating consumer group: {consumer_group}")
    for stream in streams:
        try:
            r.xgroup_create(stream, consumer_group, id='0', mkstream=True)
            print(f"✓ Created consumer group '{consumer_group}' for {stream}")
        except redis.ResponseError as e:
            if "BUSYGROUP" in str(e):
                print(f"ℹ Consumer group already exists for {stream}")
            else:
                raise
    
    # Set initial cache values
    print("\nSetting initial cache values...")
    r.hset("system:stats", mapping={
        "alerts_processed_today": 0,
        "alerts_total": 0,
        "actions_taken_today": 0,
        "false_positives_today": 0,
        "queue_depth": 0
    })
    print("✓ Initial cache values set")
    
    # Set rate limit counters
    print("Initializing rate limit counters...")
    siems = ["wazuh", "sentinelone", "sumologic", "splunk"]
    for siem in siems:
        r.set(f"ratelimit:{siem}:count", 0)
        r.set(f"ratelimit:{siem}:tokens", 100)
    print("✓ Rate limit counters initialized")
    
    print("\n✓ Redis initialization completed successfully!")


if __name__ == "__main__":
    try:
        init_redis()
    except Exception as e:
        print(f"\n✗ Error: {e}")
        sys.exit(1)
