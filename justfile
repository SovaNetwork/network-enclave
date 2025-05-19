# build rust binary
alias b := build

build:
    cargo build --release

# Run with defaults (localhost)
run:
    BIP32_SEED=000102030405060708090a0b0c0d0e0f cargo run --release

# Run for local development
run-dev:
    BIP32_SEED=000102030405060708090a0b0c0d0e0f \
    API_KEY=dev_key \
    RUST_LOG=info \
    cargo run --release -- \
        --host 127.0.0.1 \
        --port 5555 \
        --network regtest

# Run with custom host, port, and network parameters. Supply BIP32_SEED and API_KEY as environment variables.
run-custom host port network:
    BIP32_SEED="${BIP32_SEED}" \
    API_KEY="${API_KEY}" \
    RUST_LOG=info \
    cargo run --release -- \
        --host {{host}} \
        --port {{port}} \
        --network {{network}}