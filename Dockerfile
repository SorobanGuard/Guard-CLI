# Soroban Guard CLI - Multi-stage Dockerfile
#
# Build stage: compile the release binary
# Runtime stage: copy binary into a minimal distroless image
#
# Usage:
#   docker build -t soroban-guard .
#   docker run --rm soroban-guard --help

# ─────────────────────────────────────────────────────────────────────────────
# Build stage
# ─────────────────────────────────────────────────────────────────────────────
FROM rust:1.74-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy workspace files first for better caching
COPY Cargo.toml Cargo.lock ./
COPY crates/cli/Cargo.toml crates/cli/
COPY crates/analyzer/Cargo.toml crates/analyzer/
COPY crates/checks/Cargo.toml crates/checks/

# Pre-fetch dependencies (cached layer)
RUN mkdir -p crates/cli/src crates/analyzer/src crates/checks/src && \
    echo "fn main() {}" > crates/cli/src/main.rs && \
    echo "// dummy" > crates/analyzer/src/lib.rs && \
    echo "// dummy" > crates/checks/src/lib.rs && \
    cargo fetch --workspace --locked && \
    rm -rf crates/cli/src crates/analyzer/src crates/checks/src

# Copy actual source
COPY crates/cli/src crates/cli/src/
COPY crates/analyzer/src crates/analyzer/src/
COPY crates/checks/src crates/checks/src/

# Build release binary
RUN cargo build --workspace --release --locked

# ─────────────────────────────────────────────────────────────────────────────
# Runtime stage - distroless for minimal attack surface
# ─────────────────────────────────────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian12:nonroot

# Copy binary from builder
COPY --from=builder /app/target/release/soroban-guard /usr/local/bin/soroban-guard

# Default user is nonroot (UID 65532)
ENTRYPOINT ["soroban-guard"]
CMD ["--help"]