#!/bin/bash

echo "Setting up Llama 3.1 8B Inference Server"
echo "=========================================="
echo ""

# Check if model exists
MODEL_DIR="./models"
MODEL_FILE="Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf"
MODEL_PATH="$MODEL_DIR/$MODEL_FILE"

if [ ! -f "$MODEL_PATH" ]; then
    echo "❌ Model file not found: $MODEL_PATH"
    echo ""
    echo "Please download the model:"
    echo "1. Go to: https://huggingface.co/bartowski/Meta-Llama-3.1-8B-Instruct-GGUF"
    echo "2. Download: $MODEL_FILE"
    echo "3. Place in: $MODEL_DIR/"
    echo ""
    exit 1
fi

echo "✓ Model found: $MODEL_PATH"
echo ""

# Install llama-cpp-python if not installed
echo "Installing llama-cpp-python..."
pip install llama-cpp-python[server]

echo ""
echo "Starting LLM inference server..."
echo ""

# Start server
python -m llama_cpp.server \
    --model "$MODEL_PATH" \
    --host 0.0.0.0 \
    --port 8081 \
    --n_ctx 4096 \
    --n_threads 8 \
    --n_gpu_layers 35

