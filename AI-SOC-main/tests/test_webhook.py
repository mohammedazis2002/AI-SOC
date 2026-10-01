"""
Webhook Test Script
====================
Tests the ingestion webhook end-to-end without needing a running Wazuh instance.
Sends a realistic Wazuh alert to the local SOAR API and shows the response.

Run from soar-platform/backend/:
    python test_webhook.py

Requirements:
    - uvicorn api.main:app must be running on port 8000
"""

import json
import urllib.request
import urllib.error
import sys
from datetime import datetime, timezone

# ── Sample Wazuh Alert ────────────────────────────────────────────────────────
SAMPLE_WAZUH_ALERT = {
    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+0000"),
    "id": "1708123456.987654",
    "rule": {
        "level": 10,
        "description": "Multiple authentication failures followed by a success",
        "id": "2502",
        "mitre": {
            "id": ["T1110"],
            "technique": ["Brute Force"],
            "tactic": ["Credential Access"]
        },
        "groups": ["authentication_failed", "pci_dss_10.2.4", "gpg13_7.1"]
    },
    "agent": {
        "id": "001",
        "name": "web-server-prod-01",
        "ip": "10.0.1.50"
    },
    "manager": {
        "name": "wazuh-manager"
    },
    "cluster": {
        "name": "wazuh"
    },
    "data": {
        "srcip": "185.220.101.1",
        "srcport": "54321",
        "dstuser": "admin"
    },
    "decoder": {
        "name": "sshd"
    },
    "location": "/var/log/auth.log",
    "full_log": "Feb 23 05:58:42 web-server sshd[1234]: Failed password for admin from 185.220.101.1 port 54321 ssh2. 10 attempts detected."
}

# ── Test Runner ───────────────────────────────────────────────────────────────

def test_webhook(host: str = "localhost", port: int = 8000):
    url = f"http://{host}:{port}/api/v1/alerts/webhook/wazuh"
    api_key = "wazuh-api-key-12345"

    payload = json.dumps(SAMPLE_WAZUH_ALERT).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
        },
        method="POST"
    )

    print("\n" + "=" * 60)
    print("SOAR WEBHOOK TEST")
    print("=" * 60)
    print(f"URL:     POST {url}")
    print(f"API Key: {api_key}")
    print(f"Alert:   SSH brute force from 185.220.101.1 → admin")
    print("-" * 60)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode())
            print(f"Status:  {resp.status} {resp.reason}")
            print(f"\nResponse:")
            print(json.dumps(body, indent=2))

            # Check key fields
            print("\n" + "-" * 60)
            if body.get("status") == "accepted":
                print(f"✅ Alert accepted — ID: {body.get('alert_id')}")
                print(f"   Mapper:          {body.get('mapper_used')}")
                v = body.get("validation", {})
                print(f"   Validation:      {'PASS' if v.get('passed') else 'FAIL'}")
                mitre = v.get("summary", {})
                print(f"   MITRE tactic:    {mitre.get('dominant_tactic', 'unknown')}")
                if v.get("warnings"):
                    print(f"   Warnings:        {v['warnings']}")
                print("\n✅ PIPELINE IS WORKING!")
            else:
                print(f"⚠️  Unexpected response: {body.get('status')}")

    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode())
        print(f"❌ HTTP {e.code}: {e.reason}")
        print(json.dumps(body, indent=2))
        sys.exit(1)

    except urllib.error.URLError as e:
        print(f"❌ Connection failed: {e.reason}")
        print(f"   Is the API running? →  uvicorn api.main:app --port 8000 --reload")
        sys.exit(1)


def test_health(host: str = "localhost", port: int = 8000):
    url = f"http://{host}:{port}/health"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            body = json.loads(resp.read().decode())
            print(f"Health:  {body.get('status').upper()}")
            components = body.get("components", {})
            for name, info in components.items():
                status = info.get("status", "unknown")
                icon = "✅" if status == "healthy" else "⚠️ "
                print(f"  {icon}  {name}: {status}")
    except Exception as e:
        print(f"❌ Health check failed: {e}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    print("\nChecking API health first...")
    test_health(args.host, args.port)
    test_webhook(args.host, args.port)
    print("=" * 60 + "\n")
