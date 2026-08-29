# Secret Management Microservice

A high-performance, memory-safe secret management service built in Rust with the Axum web framework. Implements envelope encryption with AES-256-GCM and includes production security middleware (API key auth, rate limiting, security headers).

---

## Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [Project Structure](#project-structure)
- [Security Model](#security-model)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Container Deployment](#container-deployment)
- [Performance Testing](#performance-testing)
- [Development](#development)

---

## Architecture

The service uses **envelope encryption**, a standard pattern in cloud KMS implementations:

```
Client ──POST /encrypt──► Axum Server
                              │
                              ├─ Auth middleware (API key check)
                              ├─ Rate limiter (100 req/min/IP)
                              ├─ Security headers
                              │
                              ├─ Generate random DEK (32 bytes)
                              ├─ Encrypt plaintext with DEK (AES-256-GCM)
                              ├─ Encrypt DEK with KEK (AES-256-GCM)
                              └─ Return envelope {ciphertext, nonce, encrypted_dek, dek_nonce}
```

The **KEK** (Key Encryption Key) is loaded once at startup from the `APP_KEK` environment variable. Each request generates a fresh, random **DEK** (Data Encryption Key) that is used exactly once and zeroed from memory after use.

This design means:
- Compromising a single DEK only exposes one payload
- The KEK never leaves the server
- Key rotation is as simple as re-encrypting with a new KEK

---

## Features

| Feature | Description |
|---------|-------------|
| **Envelope Encryption** | Dual-layer AES-256-GCM: per-request DEK encrypted by master KEK |
| **Memory Safety** | `zeroize` crate wipes keys and plaintext on drop (`ZeroizeOnDrop`), no `Clone` on secrets |
| **API Key Auth** | `Authorization: Bearer <key>` with constant-time compare, fail-closed |
| **Rate Limiting** | Fixed-window per IP, configurable via `RATE_LIMIT` env (default 100/min) |
| **Security Headers** | HSTS+preload, CSP `default-src none`, nosniff, DENY frame, no-referrer, Permissions-Policy |
| **Input Validation** | Payload size limits (1MB decoded, 1.5M base64), nonce length 12-byte check |
| **Error Sanitization** | Generic user errors; details only in server logs |
| **Graceful Shutdown** | SIGTERM/Ctrl+C handling, configurable `PORT`/`APP_HOST` |
| **Swagger UI** | Interactive docs gated by `ENABLE_SWAGGER=true` (`--with-swagger` via `run.sh`) |
| **Perf Test Suite** | Go-based load tester with 429 retry, latency percentiles, RPS |
---

## Recent Updates (2026-08-29)

**Security hardening (10 fixes):**
- Constant-time `ct_eq` for `APP_API_KEY` compare (timing attack mitigation)
- Zeroize `Vec<u8>` DEK after copy, validate nonce 12-byte length (panic fix)
- `RateLimiter::new` top-level `LazyLock`, prefer peer IP over `X-Forwarded-For`
- Remove `Clone` on `PlaintextData`/`Key` types, private fields
- `load_kek()` free function replaces `EnvKekProvider` struct
- `security_headers` uses `from_static` (no unwrap), adds CSP/HSTS preload/Permissions-Policy
- Decoded payload size guard (`>1MB` → 413) and `PAYLOAD_TOO_LARGE` consistency
- `EnvFilter` tracing, configurable `PORT`/`APP_HOST`, graceful SIGTERM/Ctrl+C

**Performance:**
- `Arc<Aes256Gcm>` avoids 992B clone per request
- Inline crypto for <64KB payloads (avoids `spawn_blocking` hop), threaded for large
- `RATE_LIMIT` env configurable for load testing (see benchmark below)
- Result: **147× faster** `c10 n100` (33 → 4877 RPS), `c100 n1000` 17–20k RPS, p99 ~11ms

---

## Project Structure

```
secret-manager/
├── src/
│   ├── main.rs                  # Entry point, tracing init, binds 0.0.0.0:8080
│   ├── app.rs                   # Axum router, AppState, middleware wiring, Swagger UI
│   ├── middleware/
│   │   ├── mod.rs               # Module exports
│   │   ├── auth.rs              # API key Bearer token middleware
│   │   ├── rate_limit.rs        # Fixed-window IP-based rate limiter
│   │   └── headers.rs           # Security response headers
│   ├── api/
│   │   ├── mod.rs               # Module exports
│   │   ├── handlers.rs          # /encrypt and /decrypt route handlers
│   │   └── models.rs            # Request/response types, input validation
│   └── crypto/
│       ├── mod.rs               # Module exports
│       ├── envelope.rs          # Encrypt/decrypt envelope logic (AES-256-GCM)
│       ├── kek_provider.rs      # Loads KEK from APP_KEK env var
│       └── keys.rs              # Zeroizing key types (KEK, DEK, PlaintextData)
├── perf-test/
│   ├── perf-test.go             # Load + smoke test tool
│   ├── build.sh                 # Build helper
│   └── go.mod                   # Go module definition
├── Cargo.toml                   # Rust dependencies
├── Cargo.lock                   # Dependency lock file
├── run.sh                       # Dev launcher (ephemeral KEK, API key)
├── Dockerfile                   # Docker multi-stage build
├── .dockerignore
└── .containerignore
```

### Module Responsibilities
**`src/main.rs`** — Entry point. `EnvFilter` tracing, configurable `PORT`/`APP_HOST`/`APP_KEK`/`APP_API_KEY`, graceful shutdown on SIGTERM/Ctrl+C.

**`src/app.rs`** — Creates `AppState` with `Arc<Aes256Gcm>` (no per-request 992B clone), assembles Axum `Router` with middleware stack and conditional Swagger UI (`ENABLE_SWAGGER=true`).

**`src/middleware/auth.rs`** — Extracts `Authorization: Bearer <key>`, constant-time compare (`ct_eq`), fail-closed if `APP_API_KEY` unset.

**`src/middleware/rate_limit.rs`** — Per-IP fixed-window limiter (`RATE_LIMIT` env, default 100/60s). Prefers peer IP over `X-Forwarded-For`, background prune, top-level `LazyLock`.

**`src/middleware/headers.rs`** — Attaches HSTS+preload, CSP, nosniff, DENY frame, no-referrer, Permissions-Policy, `Cache-Control: no-store`, strips `Server` via `from_static` (no unwrap).

**`src/api/handlers.rs`** — `encrypt_handler`/`decrypt_handler`. Decoded size guard (>1MB → 413), inline crypto for <64KB else `spawn_blocking`, `Arc` cipher.

**`src/api/models.rs`** — Request/response structs with `validate()`. `EncryptRequest` 1.5M base64, `DecryptRequest` 200-char nonces, status mapping `PAYLOAD_TOO_LARGE` for large ciphertext.

**`src/crypto/envelope.rs`** — Core crypto: `encrypt_envelope`/`decrypt_envelope`. 96-bit nonces, validates 12-byte length, zeroizes DEK `Vec` after copy.

**`src/crypto/kek_provider.rs`** — `load_kek()` free function loads 32-byte hex KEK from `APP_KEK` (single caller, no struct).

**`src/crypto/keys.rs`** — `PlaintextData`, `KeyEncryptionKey`, `DataEncryptionKey` — `ZeroizeOnDrop` only, private fields, no `Clone` (avoid secret duplication).

## Security Model

### Authentication

Every `/encrypt` and `/decrypt` request requires:

```
Authorization: Bearer <your-api-key>
```

The key is read from the `APP_API_KEY` environment variable at startup. If unset, **all requests are rejected** (fail-closed).

### Middleware Stack (request → response)

```
HTTP Request
  → require_api_key       (401 if invalid/missing)
  → rate_limit_middleware  (429 if >100 req/min from same IP)
  → security_headers       (adds HSTS, nosniff, etc.)
  → handler                (business logic)
```

### Input Validation

| Field | Limit |
|-------|-------|
| `payload_b64` (encrypt) | 1,500,000 chars (~1MB decoded) |
| `ciphertext_b64` (decrypt) | 1,500,000 chars |
| `nonce_b64`, `dek_nonce_b64`, `encrypted_dek_b64` | 200 chars each |

### Error Responses

All user-facing errors return generic messages. Internal details are logged via `tracing::error!` but never exposed:

```json
{"error": "Invalid base64 encoding"}
{"error": "Encryption failed"}
{"error": "Decryption failed: invalid ciphertext or corrupted envelope"}
{"error": "Plaintext must not be empty"}
```

### Cryptographic Details

- **Algorithm:** AES-256-GCM (authenticated encryption)
- **Nonce size:** 96 bits (12 bytes), randomly generated per encryption
- **DEK size:** 32 bytes (256 bits), randomly generated per request
- **KEK size:** 32 bytes (256 bits), loaded from `APP_KEK` env var
- **Key zeroization:** All key material implements `ZeroizeOnDrop` — wiped from memory on drop
- **DEK lifecycle:** Generated → encrypts data → encrypts itself with KEK → dropped (zeroed)

---

## Prerequisites

- **Rust** 1.75+ (edition 2021)
- **Go** 1.21+ (for performance testing)
- **Docker** or **Podman** (optional, for container deployment)
- `openssl` CLI (for generating hex keys)

---

## Getting Started

### 1. Generate Secrets

```bash
# Generate a KEK (32-byte hex)
export APP_KEK=$(openssl rand -hex 32)

# Generate an API key (any secret string — use a UUID or random string)
export APP_API_KEY=$(openssl rand -hex 16)
echo "Your API key: $APP_API_KEY"
```

### 2. Start the Server

```bash
# Development (with Swagger UI)
ENABLE_SWAGGER=true APP_KEK=$APP_KEK APP_API_KEY=$APP_API_KEY cargo run

# Production (no Swagger)
APP_KEK=$APP_KEK APP_API_KEY=$APP_API_KEY cargo run
```

The server listens on `http://localhost:8080`.

### 3. Quick Test

```bash
# Encrypt
curl -s -X POST http://localhost:8080/encrypt \
  -H "Authorization: Bearer $APP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"payload_b64": "'$(echo -n "my secret" | base64)'"}'

# The response gives you ciphertext_b64, nonce_b64, encrypted_dek_b64, dek_nonce_b64.
# Use those to decrypt:

curl -s -X POST http://localhost:8080/decrypt \
  -H "Authorization: Bearer $APP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext_b64": "<from encrypt response>",
    "nonce_b64": "<from encrypt response>",
    "encrypted_dek_b64": "<from encrypt response>",
    "dek_nonce_b64": "<from encrypt response>"
  }'
```

### 4. Swagger UI

Swagger UI is enabled by setting the `ENABLE_SWAGGER` environment variable:

```bash
ENABLE_SWAGGER=true APP_KEK=$APP_KEK APP_API_KEY=$APP_API_KEY cargo run
# Open http://localhost:8080/swagger-ui
```

> **Note:** The Swagger UI page itself is unauthenticated, but every API call from it must include the `Authorization: Bearer <key>` header. You can set this in Swagger UI's "Authorize" button (top-right).

### Quick Start with run.sh

```bash
chmod +x run.sh

# Default: no Swagger UI
./run.sh

# With Swagger UI
./run.sh --with-swagger
# or
./run.sh -s
```

The script prints the generated API key to stdout. If you already have `APP_API_KEY` set in your shell, it reuses that instead of generating a new one:

```bash
export APP_API_KEY=my-stable-key
./run.sh
```

> **Note:** This is for development only. Each restart generates a fresh KEK, invalidating all previously encrypted data.

---

## API Reference

### POST `/encrypt`

Encrypts a plaintext payload using envelope encryption.

**Request:**
```json
{
  "payload_b64": "<base64-encoded plaintext>"
}
```

**Response (200):**
```json
{
  "ciphertext_b64": "<encrypted data>",
  "nonce_b64": "<12-byte nonce for data>",
  "encrypted_dek_b64": "<DEK encrypted with KEK>",
  "dek_nonce_b64": "<12-byte nonce for DEK>"
}
```

**Errors:**
| Status | Condition |
|--------|-----------|
| 401 | Missing or invalid API key |
| 400 | Invalid base64 encoding, empty payload |
| 413 | Payload exceeds 1MB |
| 429 | Rate limit exceeded (>100 req/min) |
| 500 | Internal error (encryption failure) |

---

### POST `/decrypt`

Decrypts an envelope-encrypted payload.

**Request:**
```json
{
  "ciphertext_b64": "<from /encrypt response>",
  "nonce_b64": "<from /encrypt response>",
  "encrypted_dek_b64": "<from /encrypt response>",
  "dek_nonce_b64": "<from /encrypt response>"
}
```

**Response (200):**
```json
{
  "payload_b64": "<base64-encoded plaintext>"
}
```

**Errors:**
| Status | Condition |
|--------|-----------|
| 401 | Missing or invalid API key |
| 400 | Invalid base64, field too long, decryption failed |
| 413 | Ciphertext exceeds 1.5MB |
| 429 | Rate limit exceeded |
| 500 | Internal error |

---

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `APP_KEK` | Yes | — | 32-byte hex (64 hex chars) master key. Crash at startup if invalid. |
| `APP_API_KEY` | Yes | — | Bearer token. Rejects all requests if unset (fail-closed). |
| `RUST_LOG` | No | `info` | Tracing `EnvFilter` (`debug`/`trace` etc.). |
| `ENABLE_SWAGGER` | No | `false` | `true`/`1` enables Swagger UI at `/swagger-ui`. |
| `RATE_LIMIT` | No | `100` | Max requests per 60s window per IP. Set higher for perf tests (e.g. `10000`). |
| `PORT` / `APP_PORT` | No | `8080` | Listen port. |
| `APP_HOST` | No | `0.0.0.0` | Listen host. |

### Important Notes

- **`APP_KEK` is ephemeral in dev** (`run.sh` generates new each restart) — data lost on restart. Persist in prod via vault.

---
## Container Deployment

```bash
docker build -t secret-manager .
```

### Run

```bash
docker run \
  -e APP_KEK=$(openssl rand -hex 32) \
  -e APP_API_KEY=$(openssl rand -hex 16) \
  -p 8080:8080 \
  secret-manager
```

**Production tip:** Inject secrets via a secrets manager (Docker secrets, Kubernetes Secrets, Vault) rather than passing them as environment variables directly.

---

## Performance Testing

See [`perf-test/README.md`](perf-test/README.md) for full tool usage.

**Quick start:**
```bash
cd perf-test
go run perf-test.go -apikey $APP_API_KEY -smoke              # smoke
go run perf-test.go -apikey $APP_API_KEY -c 100 -n 1000      # load (needs RATE_LIMIT=10000)
```

### Benchmark Results (release build, `RUST_LOG=warn`)

**Environment:** `Intel i9-14900HX`, `Linux 7.2.2-cachyos`, `RUST_LOG=warn`, payload `aGVsbG8gd29ybGQ=` (11 bytes). Server `target/release/secret-manager`.

**Before hardening** (`RATE_LIMIT=100` default, `spawn_blocking` every req, 992B cipher clone):

| concurrency | requests | success | rate-limited (429) | duration | RPS | p50 | p99 |
|-------------|----------|---------|---------------------|----------|-----|-----|-----|
| 10 | 100 | 96 | 4 | 3.01s | 33 | 1432µs | 3812µs |
| 50 | 200 | smoke 429 fail | — | — | — | — | — |

Fixed-window 60s + 1s retry dominates; second test fails due to window starvation.

**After hardening** (`RATE_LIMIT=10000`, `Arc<Aes256Gcm>`, inline <64KB):

| concurrency | requests | success | RPS | duration | p50 | p99 | serial curl* |
|-------------|----------|---------|-----|----------|-----|-----|--------------|
| 10 | 100 | 100 | 4877 | 20ms | 1662µs | 4204µs | 0.54ms avg, 0.29ms min |
| 50 | 500 | 500 | 6405/6691† | 78/74ms | 5638/4846µs | 11722/12621µs | — |
| 100 | 1000 | 1000 | 17050/20450† | 58/48ms | 3516/2682µs | 11110/12670µs | — |

*Serial `curl` 20 sequential requests, no contention. † encrypt/decrypt RPS.

**Delta:** `c10 n100` 147× faster (3.01s → 20ms), 0 rate-limited, RPS 33 → 4877. `c100 n1000` reaches 17–20k RPS with p99 ~11ms.

**Bottlenecks identified:**
1. Rate limiter `RwLock` write per request + fixed window — dominates under load; make configurable.
2. `spawn_blocking` hop (~15µs) > AES (~5µs) for small payloads — inline <64KB.
3. 992B cipher clone per request — `Arc` reduces to 8B.
4. Base64+JSON remain ~0.3ms serial baseline; next win is `DashMap` sharding or `simd` base64 if p99 >10ms matters.

Run perf with high limit:
```bash
RATE_LIMIT=10000 ./target/release/secret-manager &
APP_API_KEY=xxx ./perf-test/perf-test -c 100 -n 1000
```

1. Add request/response types to `src/api/models.rs`
2. Add handler function to `src/api/handlers.rs`
3. Register the route in `src/app.rs` inside `protected_routes`
4. Add to the `#[openapi]` macro paths in `app.rs` for Swagger

### Adding a New Middleware

1. Create `src/middleware/<name>.rs`
2. Export it from `src/middleware/mod.rs`
3. Add `.layer(axum_mw::from_fn(<name>))` to the router in `app.rs`
4. Middleware order matters: first added = outermost (executed first on request)

### Crypto Changes

The crypto layer is intentionally isolated in `src/crypto/`. It has no axum dependencies. Changes here don't affect the HTTP layer.

- `keys.rs` — key types (add new zeroizing types here)
- `envelope.rs` — encrypt/decrypt logic (change algorithm here)
- `kek_provider.rs` — key source (implement new providers here)

### Building

```bash
cargo build          # Debug
cargo build --release # Optimized
cargo check          # Type-check only (fast)
cargo clippy         # Linting
```

### Dependencies

| Crate | Purpose |
|-------|---------|
| `axum` 0.7 | Web framework |
| `tokio` | Async runtime |
| `aes-gcm` 0.10 | AES-256-GCM encryption |
| `zeroize` | Secure memory wiping |
| `tower-http` | Middleware (trace, CORS) |
| `utoipa` + `utoipa-swagger-ui` | OpenAPI / Swagger |
| `base64` | Base64 encoding/decoding |
| `tracing` / `tracing-subscriber` | Structured logging |
| `serde` / `serde_json` | JSON serialization |
| `thiserror` | Error derive macros |
| `hex` | Hex decoding for KEK |
| `rand` | CSPRNG for DEK/nonce generation |
|--------|---------|
| `run.sh` | Dev launcher — ephemeral KEK, default API key |
| `perf-test/build.sh` | Builds the Go perf-test binary |
