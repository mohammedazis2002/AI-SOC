import subprocess
import sys

tests = [
    "test_circuit_breaker", "test_engine_start_enqueue", "test_engine_queue_overflow",
    "test_worker_processing_success", "test_worker_processing_failure_dlq", "test_dlq_no_redis",
    "test_timed_wrapper", "test_layer_ml_success", "test_layer_ml_failure", "test_layer_ml_cb_open",
    "test_layer_temporal", "test_layer_entity", "test_layer_pattern", "test_layer_graph",
    "test_layer_behavioral", "test_deep_correlate", "test_handle_correlation_found_create",
    "test_handle_correlation_found_append"
]

for t in tests:
    print(f"Running {t}...", flush=True)
    r = subprocess.run([r"..\\venv\\Scripts\\python.exe", "-m", "pytest", f"tests/test_background_correlator.py::{t}", "-q", "--timeout=5"], capture_output=True, text=True)
    if r.returncode != 0:
        print(f"FAILED {t}:\n{r.stdout}\n{r.stderr}", flush=True)
    else:
        print(f"PASSED {t}", flush=True)
