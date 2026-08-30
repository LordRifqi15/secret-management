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
| **Envelope Encryption** | DEK per request, `CanonicalAad` (tenant/purpose/key_id/algo) length-prefixed, AAD-bound DEK wrap |
| **BSSN AEAD** | `AES-256-GCM` (default) + `ChaCha20-Poly1305` fallback via `AeadCipher` trait |
| **BSSN Asymmetric** | `RSA-OAEP ≥3072`/`X25519`, `Ed25519`/`RSASSA-PSS ≥3072` via `ed25519-dalek`/`rsa` |
| **BSSN Hash** | `SHA-256`/`SHA-512`/`SHA3-256`/`Blake2b` via `sha2`/`sha3`/`blake2` + `Hasher` trait |
| **Policy-Based** | Server-enforced `SecurityClassification::{Rendah,Tinggi,Strategis}` + `validate_primitive_compliance` |
| **Key Versioning** | Per-tenant `KekStore` (`APP_KEK_ID`/`OLD`/`<suffix>`) + `KeyService` `tenant_id → KekStore` |
| **Memory Safety** | `zeroize 1.8` + `ZeroizeOnDrop`, private fields, no `Clone` on secrets |
| **Auth + RBAC** | `Bearer` `subtle` constant-time, `APP_API_KEYS` roles + per-tenant `tenant_id` isolation |
| **Rate Limiting** | `DashMap` sharded per `IP:key` (100/min, `RATE_LIMIT` env) |
| **Security Headers** | HSTS+preload, CSP `default-src none`, nosniff, DENY, no-referrer, Permissions-Policy |
| **Input Validation** | 1MB decoded, 1.5M base64, 12-byte nonce, `DefaultBodyLimit`, canonical AAD |
| **Graceful Shutdown** | SIGTERM/Ctrl+C, `PORT`/`APP_HOST` |
| **Swagger UI** | `ENABLE_SWAGGER=true` (`--with-swagger`), `v1` schemas |
| **Perf** | `Arc` shared, inline <64KB, `DashMap` 34k RPS, `debug!` not `info!` |
---

## Recent Updates (2026-08-30) — BSSN Strategic Compliance Upgrade

Production-grade BSSN Strategic level upgrade — minimal approved subset, policy-based, canonical AAD.

**BSSN Compliance (approved crates):**
- `aes-gcm 0.10` + `chacha20poly1305 0.10` (AEAD), `rsa 0.9` OAEP ≥3072, `x25519-dalek 2.0`, `ed25519-dalek 2.1` + `rsa` PSS ≥3072, `sha2`/`sha3`/`blake2` (SHA-256/512, SHA3-256, Blake2b), `OsRng`, `zeroize 1.8`, `subtle 2.6`
- Non-goals excluded: Camellia, ARIA, Sosemanuk, HC-128, Whirlpool

**Architecture (modular):**
- `crypto/traits.rs` — `AeadCipher`, `Hasher`, `Signer`/`Verifier`, `KeyExchanger` traits
- `crypto/aad.rs` — `CanonicalAad { tenant_id, purpose, key_id, algorithm }.encode()` length-prefixed binary (4× u32 BE len + bytes, cap 128)
- `crypto/policy.rs` — `SecurityClassification::{Rendah,Tinggi,Strategis}` + `validate_primitive_compliance(algo, level)` allowlist
- `crypto/symmetric/{aes_gcm,chacha20}` + `crypto/hash` (SHA256/512, SHA3-256, Blake2b) + `crypto/envelope` upgraded
- `domain/{errors,models}` unified `CryptoError`, `services/{key_service,crypto_service}` per-tenant `KekStore`, `api/{dto,v1}` policy-based

**Canonical AAD (mandatory fix):**
- Old AAD = `key_id` only. New = `CanonicalAad.encode()` with 4 fields. Old envelopes fallback to `key_id`-only AAD if `tenant_id/purpose/algorithm` empty. Prevents metadata swap.

**Policy-based encryption:**
- `POST /v1/crypto/encrypt` now takes `{ policy:"strategis", purpose:"dukcapil-sensitive", tenant_id:"default", classification:"Strategis", data:"<b64>" }` — server decides `algorithm`/`key_id` via `Policy` + `validate_primitive_compliance`, client cannot choose weak algo.

**Multi-tenant + Key Management:**
- `KeyService { stores: HashMap<tenant_id, KekStore> }` via `APP_TENANT_<id>_KEK` or default `KekStore::from_env()`. Per-tenant KEK, `Envelope.tenant_id/purpose/algorithm` stored, `KekStore` rotation per tenant.

**New endpoints (all RBAC + rate limit + policy):**
- `POST /v1/crypto/encrypt`, `/v1/crypto/decrypt`, `/v1/crypto/sign`, `/v1/crypto/verify`, `/v1/crypto/hash` — plus legacy `/encrypt`/`/decrypt` kept for back compat.

**Verified:** `cargo check`/`clippy` clean, `v1` encrypt→decrypt roundtrip, `sign`→`verify` `valid:true`, `hash` sha256/blake2b, old `/encrypt` still works.

---

## Recent Updates (2026-08-30) — Production Crypto Hardening

Fixes all 12 real-world pitfalls from security review. Best approach = minimal AAD + versioning + RBAC, no HSM bloat.

**Crypto:**
- **AAD binding** — `encrypt_envelope(kek, key_id, plaintext)` uses `Payload { msg: dek, aad: key_id }`. Swap `encrypted_dek` between envelopes → decryption fails. `EncryptedEnvelope.key_id` + `DecryptRequest.key_id` (default `primary` for back compat).
- **Key versioning** — `KekStore` (`current_id` + `previous` map). Env: `APP_KEK` + `APP_KEK_ID` (default `primary`), optional `APP_KEK_OLD`/`APP_KEK_OLD_ID` and any `APP_KEK_<SUFFIX>` for additional old keys. `resolve_arc(&key_id)` with fallback for old `primary` envelopes. Enables rotation without data loss.
- **Zeroize + nonce** — `Vec` DEK zeroized after copy, 12-byte nonce len check before `GenericArray::from_slice`.

**Auth & Rate Limit:**
- **RBAC (decryption oracle fix)** — `ApiKeyStore` via `APP_API_KEYS="key1:both,key2:encrypt,key3:decrypt"` (fallback `APP_API_KEY` = both). Middleware checks `Role::allows(path)` → `403` if role mismatch. `both-key` 200, `enc-key` decrypt 403, `dec-key` encrypt 403 verified.
- **Per-key rate limit** — bucket key = `ip:key` (was ip only). `RATE_LIMIT=5` test: `keyA` 5 ok 2×429, `keyB` still 2×200 separate bucket. Prevents per-key brute force.

**Verified:** `cargo check` clean, smoke roundtrip with `key_id`, tamper `key_id` → `unknown key_id` / `Decryption failed` (AAD), rotation `primary→kek-2` old data still decrypts, RBAC 403/401, perf `c10 n50` 7073 RPS (AAD overhead <5%).

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

Encrypts a plaintext payload using envelope encryption. Requires `encrypt` or `both` role.

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
  "dek_nonce_b64": "<12-byte nonce for DEK>",
  "key_id": "primary"
}
```

**Errors:**
| Status | Condition |
|--------|-----------|
| 401 | Missing or invalid API key |
| 403 | Forbidden — key lacks `encrypt` role |
| 400 | Invalid base64, empty payload |
| 413 | Payload exceeds 1MB |
| 429 | Rate limit exceeded per `IP:key` |
| 500 | Internal error |

---

### POST `/decrypt`

Decrypts an envelope-encrypted payload. Requires `decrypt` or `both` role. `key_id` selects KEK via AAD check.

**Request:**
```json
{
  "ciphertext_b64": "<from /encrypt>",
  "nonce_b64": "<from /encrypt>",
  "encrypted_dek_b64": "<from /encrypt>",
  "dek_nonce_b64": "<from /encrypt>",
  "key_id": "primary"
}
```
Omit `key_id` → defaults to `primary` (back compat).

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
| 403 | Forbidden — key lacks `decrypt` role |
| 400 | Invalid base64, unknown `key_id`, AAD mismatch |
| 413 | Ciphertext exceeds 1.5MB |
| 429 | Rate limit exceeded |
| 500 | Internal error |
---

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `APP_KEK` | Yes | — | 32-byte hex (64 hex) master key. Crash if invalid. |
| `APP_KEK_ID` | No | `primary` | Current KEK id stored in `key_id` envelope field. |
| `APP_KEK_OLD` | No | — | Previous KEK hex for rotation (decrypt old). |
| `APP_KEK_OLD_ID` | No | `previous` | Id for `APP_KEK_OLD`. |
| `APP_KEK_<SUFFIX>` | No | — | Any additional old keys: suffix → id (`_→-`, lower). e.g. `APP_KEK_V2` → `v2`. |
| `APP_API_KEY` | Yes* | — | Bearer token `both` role. *Required if `APP_API_KEYS` unset. |
| `APP_API_KEYS` | No | — | Multi-key RBAC: `key1:both,key2:encrypt,key3:decrypt`. Overrides `APP_API_KEY`. |
| `RUST_LOG` | No | `info` | `EnvFilter` (`debug`/`trace`). |
| `ENABLE_SWAGGER` | No | `false` | `true`/`1` enables `/swagger-ui`. |
| `RATE_LIMIT` | No | `100` | Max per 60s per `IP:key` composite. `10000` for perf. |
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

**After hardening — first pass (2026-08-29)** (`RATE_LIMIT=10000`, `Arc`, inline <64KB):

| concurrency | requests | success | RPS | duration | p50 | p99 | serial curl* |
|-------------|----------|---------|-----|----------|-----|-----|--------------|
| 10 | 100 | 100 | 4877 | 20ms | 1662µs | 4204µs | 0.54ms avg, 0.29ms min |
| 50 | 500 | 500 | 6405/6691† | 78/74ms | 5638/4846µs | 11722/12621µs | — |
| 100 | 1000 | 1000 | 17050/20450† | 58/48ms | 3516/2682µs | 11110/12670µs | — |

**After production hardening (2026-08-30)** — AAD-bound `key_id`, `KekStore` rotation, RBAC `APP_API_KEYS`, per-key rate limit `IP:key`:

| concurrency | requests | success | RPS (enc / dec) | duration (enc / dec) | p50 (enc / dec) | p99 (enc / dec) |
|-------------|----------|---------|-----------------|----------------------|-----------------|-----------------|
| 10 | 100 | 100 | 8139 / 6061 | 12ms / 16ms | 912µs / 1408µs | 3060µs / 2798µs |
| 50 | 500 | 500 | 10106 / 6386 | 49ms / 78ms | 2669µs / 5481µs | 13247µs / 13942µs |
| 100 | 1000 | 1000 | 10953 / 11832 | 91ms / 84ms | 7216µs / 4036µs | 23462µs / 26048µs |

Serial baseline (20 sequential, no contention): small 11B → **0.81ms avg** (0.65ms min); 100KB → **1.98ms avg**; 1MB → **4.66ms avg**. `perf-test` now carries `key_id` through roundtrip.

**After DashMap + debug log (2026-08-30 final)** — `DashMap` sharded map replaces global `RwLock<HashMap>`, per-request `info!` → `debug!`:

| concurrency | requests | success | RPS (enc / dec) | duration (enc / dec) | p50 (enc / dec) | p99 (enc / dec) | serial |
|-------------|----------|---------|-----------------|----------------------|-----------------|-----------------|--------|
| 10 | 100 | 100 | 7511 / 6454 | 13ms / 15ms | 1132µs / 1315µs | 3286µs / 2783µs | 0.34ms avg |
| 50 | 500 | 500 | 11748 / 8112 | 42ms / 61ms | 2890µs / 4242µs | 8509µs / 12768µs | — |
| 100 | 1000 | 1000 | **34009 / 35956** | 29ms / 27ms | 948µs / 1776µs | 6021µs / 5744µs | — |

Delta vs `RwLock` at `c100 n1000`: **3.1× RPS** (10953→34009 enc, 11832→35956 dec), **p50 7.6×** (7216→948 enc), **p99 3.9×** (23462→6021 enc), histogram 1000/1000 in 0–10ms (was 658). Serial 0.81→0.34ms (2.4×) from `debug!` log.

**Delta vs before (RATE_LIMIT=100):** `c10 n100` 147× faster (3.01s → 13ms), 0 rate-limited, RPS 33 → 7511. `c100 n1000` 34k RPS sustained with p99 <6ms.

**Bottlenecks — fixed vs remaining:**
1. ~~`RwLock<HashMap>` global write~~ → **fixed** `DashMap` sharded + `IP:key` + `RATE_LIMIT` env — c100 RPS 10k→34k, p99 23ms→6ms, 1000/1000 in 0–10ms.
2. ~~`spawn_blocking` every req~~ → **fixed** inline <64KB, threaded >64KB (100KB 1.98ms, 1MB 4.66ms).
3. ~~992B cipher clone~~ → **fixed** `Arc<Aes256Gcm>` 8B.
4. **Remaining:** Base64+JSON ~0.34ms serial. Next win `simd` base64 or `serde` zero-copy if p99 <5ms needed.
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
