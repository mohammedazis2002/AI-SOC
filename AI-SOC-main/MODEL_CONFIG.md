# Quick Reference: Model Configuration

## Current Setup (Development)
**Model:** Llama 3.1 8B Instruct (Quantized)
**Configuration:** `llama3.1:8b-instruct-q4_K_M`

### Environment Variable
```bash
LLM_MODEL_NAME=llama3.1:8b-instruct-q4_K_M
```

### Performance Specs
- ⚡ **Latency**: 1-3 seconds per log
- 🎯 **Accuracy**: 85-90%
- 💾 **Model Size**: 4.9GB
- ✅ **Timeout**: 300 seconds (5 minutes)

---

## Production Setup (Future)
**Model:** Llama 3.1 70B Instruct (Quantized)
**Configuration:** `llama3.1:70b-instruct-q4_K_M`

### To Switch to Production Model
```bash
# Pull the 70B model
docker-compose exec ollama ollama pull llama3.1:70b-instruct-q4_K_M

# Update environment
LLM_MODEL_NAME=llama3.1:70b-instruct-q4_K_M
```

### Production Specs
- 🎯 **Accuracy**: 92-95% (highest)
- ⏱️ **Latency**: 10-20 seconds per log
- 💾 **Model Size**: ~40GB
- ⚠️ **Requirements**: High-end GPU (24GB+ VRAM)

### When to Switch
- When accuracy is more critical than speed
- For batch processing (offline analysis)
- When you have GPU resources available
- For critical/high-severity alerts only

---

## Testing Commands

### Test Current Model
```bash
python test_ai_mapper.py
```

### Test with Different Model
```bash
# Temporarily test another model
$env:LLM_MODEL_NAME='llama3.1:70b-instruct-q4_K_M'
python test_ai_mapper.py
```

### Check Model List
```bash
docker-compose exec ollama ollama list
```

---

## Model Comparison

| Aspect | Llama 3.1 8B (Dev) | Llama 3.1 70B (Prod) |
|--------|-------------------|---------------------|
| Speed | ⚡⚡⚡ Fast (1-3s) | ⏱️ Slower (10-20s) |
| Accuracy | ✅ Good (85-90%) | 🎯 Excellent (92-95%) |
| Size | 💾 Small (4.9GB) | 💾 Large (40GB) |
| GPU Needed | ❌ No | ✅ Yes (24GB+) |
| Use Case | Development, Testing | Production, Critical Alerts |

---

## Troubleshooting

### If Model is Slow
```bash
# Check if model is loaded
docker-compose exec ollama ollama ps

# Restart Ollama
docker-compose restart ollama
```

### If Accuracy is Low
- Switch to 70B model for better accuracy
- Or fine-tune a custom model on your data
- Add few-shot examples to the prompt

### If Out of Memory
- Use smaller quantization (q4_0 instead of q4_K_M)
- Reduce context window
- Use 8B model instead of 70B
