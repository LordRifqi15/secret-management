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
| **Memory Safety** | `zeroize` crate wipes keys and plaintext on drop (`ZeroizeOnDrop`) |
| **API Key Auth** | `Authorization: Bearer <key>` middleware, fail-closed |
| **Rate Limiting** | Fixed-window: 100 requests/minute per client IP |
| **Security Headers** | HSTS, X-Content-Type-Options, X-Frame-Options, etc. |
| **Input Validation** | Payload size limits (1MB decoded), field length checks |
| **Error Sanitization** | User-facing errors are generic; details go to server logs only |
| **CORS** | Configurable cross-origin policy via `tower-http` |
| **Swagger UI** | Interactive API docs, enabled via `ENABLE_SWAGGER=true` |
| **Perf Test Suite** | Go-based load tester with smoke test, auth support, and CLI flags |

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
**`src/main.rs`** — Entry point. Initializes tracing, builds the app, binds to `0.0.0.0:8080`.

**`src/app.rs`** — Creates `AppState` (pre-expanded AES cipher), assembles the Axum `Router` with middleware stack and conditional Swagger UI (`ENABLE_SWAGGER=true`).
**`src/middleware/auth.rs`** — Extracts `Authorization: Bearer <key>` header, compares against `APP_API_KEY` env var. Fail-closed: no key configured = all requests rejected.

**`src/middleware/rate_limit.rs`** — Per-IP fixed-window rate limiter (100 req/60s). Extracts client IP from `X-Forwarded-For` or connecting socket. Background task prunes stale entries.

**`src/middleware/headers.rs`** — Attaches security headers (HSTS, nosniff, DENY frame, no-cache, XSS protection) to every response. Strips `Server` header.

**`src/api/handlers.rs`** — `encrypt_handler` and `decrypt_handler`. Validate input, delegate crypto to `envelope.rs` via `spawn_blocking`, return generic errors to client.

**`src/api/models.rs`** — Request/response structs with `validate()` methods. `EncryptRequest` capped at 1.5M chars base64 (~1MB decoded). `DecryptRequest` field lengths capped at 200 chars.

**`src/crypto/envelope.rs`** — Core crypto: `encrypt_envelope` (generate DEK → encrypt data → encrypt DEK) and `decrypt_envelope` (decrypt DEK → decrypt data). All AES-256-GCM with 96-bit nonces.

**`src/crypto/kek_provider.rs`** — `EnvKekProvider` loads and decodes the 32-byte hex KEK from `APP_KEK` env var at startup.

**`src/crypto/keys.rs`** — `PlaintextData`, `KeyEncryptionKey`, `DataEncryptionKey` — all `ZeroizeOnDrop`. Memory-safe wrappers around byte arrays.

---

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
| `APP_KEK` | Yes | — | 32-byte hex string (64 hex chars). Master key for envelope encryption. |
| `APP_API_KEY` | Yes | — | Bearer token for API authentication. Rejects all requests if unset. |
| `RUST_LOG` | No | `info` | Tracing filter (`debug`, `trace`, etc.). |
| `ENABLE_SWAGGER` | No | `false` | Set to `true` or `1` to enable Swagger UI at `/swagger-ui`. |
### Important Notes

- **`APP_KEK`** must be exactly 64 hex characters (32 bytes). The service crashes at startup otherwise.
- **`APP_KEK` is ephemeral in dev mode** (`run.sh`). All encrypted data is lost on restart. Use a persistent value in production.
- **`APP_API_KEY`** should be a strong, random string. The `run.sh` script defaults to `change-me-in-production` — override this.

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

See [`perf-test/README.md`](perf-test/README.md) for full usage of the Go-based load tester.

**Quick start:**

```bash
cd perf-test

# Smoke test (single encrypt → decrypt roundtrip)
go run perf-test.go -apikey $APP_API_KEY -smoke

# Full load test (100 concurrent, 1000 requests)
go run perf-test.go -apikey $APP_API_KEY -c 100 -n 1000
```

---

## Development

### Adding a New Endpoint

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
