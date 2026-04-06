# Secret Management Microservice

A high-performance, memory-safe Secret Management Microservice built in Rust using the Axum framework. 

## Features
- **Memory Safety:** Uses the `zeroize` crate to ensure cryptographic keys and plaintexts are securely wiped from memory immediately after use, preventing memory leaks of sensitive data.
- **Envelope Encryption:** Implements dual-layer AES-256-GCM encryption. Generates temporary Data Encryption Keys (DEKs) on-the-fly and encrypts them with a master Key Encryption Key (KEK).
- **Abstracted Key Management:** Pre-architected to integrate with solutions like HashiCorp Vault. Currently supports an environment-variable injected KEK.
- **REST API:** High-throughput `/encrypt` and `/decrypt` endpoints.
- **Swagger UI:** Auto-generated interactive OpenAPI documentation.

## Prerequisites
- Rust and Cargo
- Docker or Podman (optional, for deploying as a container)

## Getting Started

### Local Development

1. Generate a fast testing KEK matching a 32-byte hex format.
   ```bash
   export APP_KEK=$(openssl rand -hex 32)
   ```
2. Run Server: 
   ```bash
   RUST_LOG=info cargo run
   ```
3. Open Swagger UI to interact with the API: Navigate to `http://localhost:8080/swagger-ui` in your browser.

### Container Deployment
Ready-made `Dockerfile` and `Containerfile` are provided for containerized workflows natively supporting Docker and Podman multi-stage builds.

```bash
# Docker Build
docker build -t secret-manager .

# Podman Build
podman build -f Containerfile -t secret-manager .
```

To run the container:
```bash
docker run -e APP_KEK=$(openssl rand -hex 32) -p 8080:8080 secret-manager
```
