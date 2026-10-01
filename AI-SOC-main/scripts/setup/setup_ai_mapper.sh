#!/bin/bash
# Setup script for Ollama AI Mapper

set -e

echo "=========================================="
echo "Setting up Ollama AI Mapper"
echo "=========================================="

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Change to project root
cd "$(dirname "$0")/../.."

# Step 1: Stop existing services
echo -e "\n${YELLOW}Step 1: Stopping existing services...${NC}"
docker-compose down

# Step 2: Start Ollama service
echo -e "\n${YELLOW}Step 2: Starting Ollama service...${NC}"
docker-compose up -d ollama

# Wait for Ollama to be ready
echo "Waiting for Ollama to start (this may take 30-60 seconds)..."
for i in {1..60}; do
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Ollama is ready!${NC}"
        break
    fi
    if [ $i -eq 60 ]; then
        echo -e "${RED}✗ Ollama failed to start after 60 seconds${NC}"
        echo "Check logs with: docker-compose logs ollama"
        exit 1
    fi
    sleep 1
    echo -n "."
done

# Step 3: Pull the model
echo -e "\n${YELLOW}Step 3: Pulling Mistral model...${NC}"
echo "This will download ~4GB and may take 5-15 minutes depending on your connection"
docker-compose exec ollama ollama pull mistral:latest

# Verify model was pulled
echo -e "\n${YELLOW}Verifying installed models:${NC}"
docker-compose exec ollama ollama list

# Step 4: Test the connection
echo -e "\n${YELLOW}Step 4: Testing Ollama API...${NC}"
if curl -s http://localhost:11434/v1/models | grep -q "mistral"; then
    echo -e "${GREEN}✓ Ollama API is responding correctly${NC}"
else
    echo -e "${RED}✗ Ollama API test failed${NC}"
    exit 1
fi

# Step 5: Start all services
echo -e "\n${YELLOW}Step 5: Starting all services...${NC}"
docker-compose up -d

# Wait for API to be ready
echo "Waiting for API service to start..."
sleep 10

# Step 6: Run the test script
echo -e "\n${YELLOW}Step 6: Running AI Mapper tests...${NC}"
echo "This will test the complete AI mapping pipeline..."
sleep 2

docker-compose exec api python test_ai_mapper_complete.py

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo -e "\n${GREEN}=========================================="
    echo "🎉 Setup Complete - All Tests Passed!"
    echo "==========================================${NC}"
    echo ""
    echo "Your AI Mapper is ready to use!"
    echo ""
    echo "Next steps:"
    echo "  1. Integrate AI mapper into your ingestion pipeline"
    echo "  2. Configure alert rules in your dashboard"
    echo "  3. Set up human review workflow"
    echo ""
    echo "Useful commands:"
    echo "  - Test AI mapper:"
    echo "    docker-compose exec api python test_ai_mapper_complete.py"
    echo ""
    echo "  - View Ollama logs:"
    echo "    docker-compose logs -f ollama"
    echo ""
    echo "  - Pull different model (faster/smaller):"
    echo "    docker-compose exec ollama ollama pull phi3:mini"
    echo ""
    echo "  - List available models:"
    echo "    docker-compose exec ollama ollama list"
    echo ""
else
    echo -e "\n${RED}=========================================="
    echo "⚠️  Setup completed with test failures"
    echo "==========================================${NC}"
    echo ""
    echo "Some tests failed. Check the output above for details."
    echo "Common issues:"
    echo "  - Model still downloading (wait and retry)"
    echo "  - Timeout issues (increase LLM_TIMEOUT in docker-compose.yml)"
    echo "  - Memory issues (Ollama needs ~4GB RAM minimum)"
    echo ""
fi

exit $EXIT_CODE