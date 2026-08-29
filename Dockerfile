# Build stage
FROM rust:1.80-slim AS builder
WORKDIR /app
# Cache deps — dummy build
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src
COPY src src
RUN touch src/main.rs && cargo build --release

# Production stage
FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/secret-manager .
EXPOSE 8080
ENV RUST_LOG=info
CMD ["./secret-manager"]
