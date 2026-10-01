"""
Startup Script for FP Detector System

Launches all FP detector services:
1. FP Detector API (port 5006)
2. Analyst Labeling UI (port 7860)
3. Monitoring Dashboard (port 7861)
"""

import subprocess
import sys
import time
import os

print("="*60)
print("      FP DETECTOR SYSTEM - STARTUP")
print("="*60)

# Services to start
services = [
    {
        'name': 'FP Detector API',
        'command': [sys.executable, '-m', 'uvicorn', 
                   'services.ml.false_positive_detection.fp_detector_service:app',
                   '--host', '0.0.0.0', '--port', '5004'],
        'port': 5004,
        'url': 'http://localhost:5004/health'
    },
    {
        'name': 'FP Labeling UI',
        'command': [sys.executable, 'fp_labeling_ui.py'],
        'port': 7860,
        'url': 'http://localhost:7860'
    },
    {
        'name': 'Monitoring Dashboard',
        'command': [sys.executable, 'fp_monitoring_dashboard.py'],
        'port': 7861,
        'url': 'http://localhost:7861'
    }
]

processes = []

try:
    for service in services:
        print(f"\n🚀 Starting {service['name']} on port {service['port']}...")
        
        process = subprocess.Popen(
            service['command'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        processes.append(process)
        time.sleep(2)  # Wait for service to start
        
        print(f"   ✅ {service['name']} started")
        print(f"   📍 Access at: {service['url']}")
    
    print("\n" + "="*60)
    print("✅ ALL SERVICES STARTED SUCCESSFULLY")
    print("="*60)
    print("\n📋 Service URLs:")
    print("   • FP Detector API:     http://localhost:5004")
    print("   • Labeling UI:         http://localhost:7860")
    print("   • Monitoring Dashboard: http://localhost:7861")
    print("\n💡 Press Ctrl+C to stop all services")
    print("="*60)
    
    # Keep script running
    while True:
        time.sleep(1)

except KeyboardInterrupt:
    print("\n\n🛑 Shutting down services...")
    for process in processes:
        process.terminate()
    print("✅ All services stopped.")

except Exception as e:
    print(f"\n❌ Error: {e}")
    for process in processes:
        process.terminate()
    sys.exit(1)
