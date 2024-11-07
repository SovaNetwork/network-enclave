# Build stage
FROM rust:1.81-slim-bookworm as builder

# Create a new empty shell project
WORKDIR /usr/src/app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src
COPY justfile ./

# Build the application
RUN cargo build --release

# Final stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /usr/src/app/target/release/corsa-enclave /usr/local/bin/

# Create a non-root user with specific UID
RUN useradd -m -u 1001 enclave
USER enclave

# Set environment variables
ENV RUST_LOG=info

# Expose the service port
EXPOSE 5555

# Run the binary
CMD ["corsa-enclave"]