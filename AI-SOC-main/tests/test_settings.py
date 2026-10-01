"""Test settings loading"""
import sys
sys.path.insert(0, 'backend')

try:
    from config.settings import settings
    print("✅ Settings loaded successfully!")
    print(f"MongoDB Host: {settings.mongodb_host}")
    print(f"Redis Host: {settings.redis_host}")
    print(f"LLM URL: {settings.llm_service_url}")
except Exception as e:
    print(f"❌ Error loading settings: {e}")
    import traceback
    traceback.print_exc()
