#!/usr/bin/env python3
"""
Ollama Model Setup Script
==========================
Imports the local Meta-Llama-3.1-8B-Instruct GGUF file into Ollama
so it's available as 'llama3.1:8b' without any download required.

Run AFTER docker-compose up:
    python scripts/setup/setup_ollama_model.py

The GGUF file is already at:
    ./models/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf
"""

import subprocess
import sys
import time
import urllib.request
import json

OLLAMA_URL = "http://localhost:11434"
MODEL_NAME = "llama3.1:8b"
GGUF_PATH_IN_CONTAINER = "/models/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf"

MODELFILE_CONTENT = f"""FROM {GGUF_PATH_IN_CONTAINER}

PARAMETER temperature 0.1
PARAMETER num_ctx 4096
PARAMETER stop "<|eot_id|>"
PARAMETER stop "<|start_header_id|>"

SYSTEM "You are a cybersecurity expert assistant specializing in threat analysis, incident response, and security operations."
"""


def wait_for_ollama(timeout: int = 120):
    """Wait until Ollama is responding"""
    print(f"Waiting for Ollama at {OLLAMA_URL}...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=3) as resp:
                if resp.status == 200:
                    print("✅ Ollama is ready")
                    return True
        except Exception:
            pass
        time.sleep(3)
        print("  Still waiting...")
    print("❌ Ollama did not become ready in time")
    return False


def model_exists() -> bool:
    """Check if model is already imported"""
    try:
        with urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=5) as resp:
            data = json.loads(resp.read())
            models = [m["name"] for m in data.get("models", [])]
            return any(MODEL_NAME in m for m in models)
    except Exception:
        return False


def create_model_via_api():
    """Create model in Ollama using the Modelfile"""
    print(f"\nImporting {MODEL_NAME} from local GGUF file...")
    print(f"  Source: {GGUF_PATH_IN_CONTAINER}")
    print("  This may take 1-2 minutes (first time only)...\n")

    payload = json.dumps({
        "name": MODEL_NAME,
        "modelfile": MODELFILE_CONTENT,
        "stream": False
    }).encode()

    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/create",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            result = json.loads(resp.read())
            if result.get("status") == "success":
                print(f"✅ Model '{MODEL_NAME}' imported successfully!")
                return True
            else:
                print(f"⚠️  Unexpected response: {result}")
                return False
    except Exception as e:
        print(f"❌ Failed to create model via API: {e}")
        print("\nTrying via docker exec instead...")
        return create_model_via_docker()


def create_model_via_docker():
    """Fallback: create model via docker exec"""
    # Write Modelfile inside container and run ollama create
    modelfile_cmd = MODELFILE_CONTENT.replace('"', '\\"').replace('\n', '\\n')

    cmd = [
        "docker", "exec", "soar-ollama",
        "sh", "-c",
        f'printf "{modelfile_cmd}" > /tmp/Modelfile && ollama create {MODEL_NAME} -f /tmp/Modelfile'
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode == 0:
        print(f"✅ Model '{MODEL_NAME}' created via docker exec!")
        return True
    else:
        print(f"❌ docker exec failed: {result.stderr}")
        return False


def test_model():
    """Quick inference test"""
    print(f"\nTesting {MODEL_NAME} inference...")
    payload = json.dumps({
        "model": MODEL_NAME,
        "prompt": "Reply with exactly: SOAR_TEST_OK",
        "stream": False,
        "options": {"num_predict": 10}
    }).encode()

    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read())
            response_text = result.get("response", "").strip()
            print(f"  Model response: '{response_text}'")
            print("✅ LLM inference is working!")
            return True
    except Exception as e:
        print(f"⚠️  Test inference failed: {e}")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("SOAR Platform - Ollama Model Setup")
    print("=" * 60)

    if not wait_for_ollama():
        print("\nMake sure Ollama is running:")
        print("  docker-compose up -d ollama")
        sys.exit(1)

    if model_exists():
        print(f"✅ Model '{MODEL_NAME}' is already imported. Skipping.\n")
        test_model()
    else:
        if create_model_via_api():
            test_model()
        else:
            print("\n❌ Model setup failed. Manual steps:")
            print("  1. docker exec -it soar-ollama sh")
            print(f"  2. ollama create {MODEL_NAME} -f /models/Modelfile")
            sys.exit(1)

    print("\n" + "=" * 60)
    print("Model is ready. Update .env:")
    print(f"  LLM_MODEL_NAME={MODEL_NAME}")
    print("=" * 60)
