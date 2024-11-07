# build rust binary
alias b := build

build:
    cargo build --release

run:
    cargo run --release

# Run for local development
run-dev:
    RUST_LOG=info cargo run --release -- \
        --host 127.0.0.1 \
        --port 5555 \
        --seed 000102030405060708090a0b0c0d0e0f