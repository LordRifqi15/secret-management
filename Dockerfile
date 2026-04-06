# Build stage
FROM rust:1.80-slim AS builder

WORKDIR /app

# Install pkg-config and libssl-dev if required by dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy dependency manifests
COPY Cargo.toml Cargo.lock ./

# Create dummy src to build dependencies and cache them
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy real source code
COPY src src

# Touch main.rs to force Cargo to recompile the project itself, instead of relying on the cached dummy build
RUN touch src/main.rs && cargo build --release

# Production stage
FROM debian:bookworm-slim

WORKDIR /app

# Install typical run-time dependencies (e.g. ca-certificates)
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder environment
COPY --from=builder /app/target/release/secret-manager .

# Expose API port
EXPOSE 8080

# Environment defaults
ENV RUST_LOG=info

CMD ["./secret-manager"]
