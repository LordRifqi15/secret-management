# Performance Test Tool

A Go-based load testing and smoke testing tool for the Secret Management Microservice.

## What It Does

1. **Smoke Test** — Single encrypt → decrypt roundtrip. Verifies the service is working and your API key is correct.
2. **Load Test** — Sends N requests with C concurrent goroutines to `/encrypt` then `/decrypt`. Reports latency percentiles, RPS, and histograms.

The smoke test always runs first. Load tests only run if smoke passes.

## Prerequisites

- Go 1.21+
- The secret-manager service running and accessible
- A valid API key (`APP_API_KEY`)

## Build

```bash
# Using the helper script
chmod +x build.sh
./build.sh

# Or manually
go build -o perf-test perf-test.go
```

## Usage

### Smoke Test Only

Tests a single encrypt → decrypt roundtrip. Good for verifying setup.

```bash
go run perf-test.go -apikey <your-api-key> -smoke
```

Expected output on success:
```
=== Smoke Test: single encrypt + decrypt ===
  Encrypting: "hello secret-manager" (base64: aGVsbG8gc2VjcmV0LW1hbmFnZXI=)
  ✓ Encrypted OK — ciphertext_b64=dGhpcyBpcyBhIHRlc3QgY2lwaGVydGV4dA...
  ✓ Decrypted OK — payload: "hello secret-manager"
  ✓ Roundtrip verified — plaintext matches!
=== Smoke Test PASSED ===
```

### Full Load Test

Runs smoke test first, then load test on both `/encrypt` and `/decrypt`:

```bash
go run perf-test.go -apikey <your-api-key>
```

### Custom Parameters

```bash
go run perf-test.go \
  -apikey <your-api-key> \
  -url http://localhost:8080 \
  -c 500 \
  -n 5000
```

### Using Environment Variable

Instead of `-apikey`, you can export the key:

```bash
export APP_API_KEY=<your-api-key>
go run perf-test.go -smoke
go run perf-test.go -c 200 -n 2000
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-apikey` | `""` (falls back to `APP_API_KEY` env) | API key for Bearer authentication |
| `-url` | `http://localhost:8080` | Base URL of the secret-manager service |
| `-c` | `100` | Concurrency — number of parallel goroutines |
| `-n` | `1000` | Total number of requests per endpoint |
| `-smoke` | `false` | Run smoke test only (no load test) |

## Output

### Smoke Test Output

```
=== Smoke Test: single encrypt + decrypt ===
  Encrypting: "hello secret-manager" (base64: ...)
  ✓ Encrypted OK — ciphertext_b64=...
  ✓ Decrypted OK — payload: "hello secret-manager"
  ✓ Roundtrip verified — plaintext matches!
=== Smoke Test PASSED ===
```

### Load Test Output

```
=== Running /encrypt Performance Test ===
Using captured envelope: ciphertext_b64=...
------------------------------------------------------------
Total Requests: 1000
Success: 998, Failed: 0 (0.00% errors)
Rate Limited (429): 2
Total Test Duration: 2.341s
Requests per Second (RPS): 427.12

Latency Metrics (microseconds):
  Average: 231 µs
  Min: 89 µs
  Max: 1823 µs
  Std Dev: 142 µs

Percentiles:
  P50: 198 µs
  P90: 345 µs
  P95: 412 µs
  P99: 890 µs

Histogram (buckets of 10ms):
  0–10 ms : 998
  10–20 ms : 2
------------------------------------------------------------
```

**Rate limiting:** When a request hits 429 (Too Many Requests), the tool waits 1 second and retries (up to 3 times per request). Retried requests are counted in `Rate Limited (429)` and their retry latency is included in the total. If all retries fail, the request is counted as failed.

| Metric | What It Means |
|--------|---------------|
| **RPS** | Requests per second — higher is better |
| **P50/P90/P95/P99** | Latency at each percentile — lower is better |
| **Std Dev** | Consistency — lower means more predictable |
| **Error Rate** | Failed requests — should be 0% |

## Error Scenarios

### 401 Unauthorized
```
Request failed: status=401, body={"error":"Unauthorized"}
```
Your API key doesn't match `APP_API_KEY` on the server. Double-check the key.

### 429 Too Many Requests
```
Request failed: status=429, body={"error":"Too Many Requests"}
```
You hit the rate limit (100 req/min per IP). Lower `-c` or `-n`, or wait a minute.

### Connection Refused
```
Request failed: err=Post "http://localhost:8080/encrypt": dial tcp 127.0.0.1:8080: connect: connection refused
```
The service isn't running. Start it first with `cargo run` or `./run.sh`.

### 500 Internal Server Error
```
Request failed: status=500, body={"error":"Internal server error"}
```
`APP_KEK` is not set or invalid on the server. Restart the service with a valid key.

## Example Workflows

### Quick Health Check

```bash
go run perf-test.go -apikey $APP_API_KEY -smoke
```

### Benchmark Different Concurrency Levels

```bash
for c in 10 50 100 500 1000; do
  echo "--- Concurrency: $c ---"
  go run perf-test.go -apikey $APP_API_KEY -c $c -n 1000
done
```

### Test Against Remote Server

```bash
go run perf-test.go \
  -apikey $APP_API_KEY \
  -url https://secret-manager.example.com \
  -c 200 \
  -n 5000
```

## Architecture

```
main()
  │
  ├── parse flags / env
  ├── runSmokeTest()
  │     POST /encrypt → POST /decrypt → compare plaintext
  │
  ├── runEncryptTest()
  │     POST /encrypt × N (C concurrent)
  │     captures first response for decrypt test
  │     reportResults()
  │
  └── runDecryptTest()
        POST /decrypt × N (C concurrent)
        uses captured encrypt envelope
        reportResults()
```

The tool uses a shared `sync.Once` to capture the first successful `/encrypt` response. This envelope is then reused for all `/decrypt` load test requests, so the decrypt test doesn't need a separate setup call.
