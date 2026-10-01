#!/bin/bash

echo "Checking SOAR platform file structure..."
echo ""

files=(
    "backend/schemas/__init__.py"
    "backend/schemas/ulf_schema.py"
    "backend/services/__init__.py"
    "backend/services/ingestion/__init__.py"
    "backend/services/ingestion/wazuh_mapper.py"
    "backend/examples/wazuh_alert_example.json"
    "backend/test_wazuh_mapper.py"
    "backend/api/__init__.py"
    "backend/api/main.py"
)

for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo "✓ $file"
    else
        echo "✗ MISSING: $file"
    fi
done

echo ""
echo "Checking directory structure..."
docker-compose exec api ls -la /app/schemas/ 2>/dev/null || echo "Could not check Docker container"
