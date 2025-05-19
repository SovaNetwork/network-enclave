# Use cargo-chef to plan the build
FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

# Create a recipe for caching dependencies
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Build dependencies - this is the caching layer!
FROM chef AS builder
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is cached unless Cargo.lock changes
RUN cargo chef cook --release --recipe-path recipe.json

# Build application
COPY . .
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*
RUN cargo build --release

# Create the runtime image using Distroless (very minimal, more secure)
FROM gcr.io/distroless/cc-debian12

# Copy the binary from builder
COPY --from=builder /app/target/release/network-enclave /usr/local/bin/

# Expose the service port
EXPOSE 5555

# Run the binary
ENTRYPOINT ["/usr/local/bin/network-enclave"]