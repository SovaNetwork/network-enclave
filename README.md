# Network Enclave

Network Enclave is a Bitcoin signing service used by the Sova Network that hosts the network master key and provides APIs for derivation of Bitcoin addresses from Ethereum addresses and signing of Bitcoin transactions. This service uses Bitcoin's BIP32 hierarchical deterministic wallets to deterministically derive Bitcoin addresses and keys from Ethereum addresses.

## Features

- Derive Bitcoin addresses from Ethereum addresses
- Sign Bitcoin transactions using keys derived from Ethereum addresses
- Support for multiple Bitcoin networks (Regtest, Testnet, Signet, Mainnet)
- Secure API key authentication for protected endpoints

## Getting Started

### Prerequisites

Ensure you have the following installed on your machine:

- Rust and Cargo
- [Just](https://just.systems/) - A command runner (optional, for convenience)

### Clone the Repository

First, clone the repository to your local machine:

```sh
git clone https://github.com/OnCorsa/network-enclave.git
cd network-enclave
```

### Environment Variables

The service requires the following environment variables:

- `BIP32_SEED` - Hex-encoded seed for the BIP32 master key (mandatory)
- `API_KEY` - API key for protected endpoints (if not set, protected endpoints will be inaccessible)
- `RUST_LOG` - Log level (e.g., info, debug, warn) - defaults to info

### Build and Run
```sh
#build
cargo build --release

# run
BIP32_SEED=000102030405060708090a0b0c0d0e0f API_KEY=your_api_key cargo run --release
```
or if you have Just installed:

```sh
BIP32_SEED=000102030405060708090a0b0c0d0e0f API_KEY=your_api_key just run
```

### Command-Line Arguments

The service supports the following command-line arguments:

- `--host` - Host address to bind to (default: 127.0.0.1)
- `--port` - Port to listen on (default: 5555)
- `--network` - Bitcoin network to use (options: regtest, testnet, signet, mainnet; default: regtest)

Example with custom arguments:
```
BIP32_SEED=000102030405060708090a0b0c0d0e0f API_KEY=your_api_key cargo run --release -- --host 0.0.0.0 --port 8080 --network regtest
```

## API Endpoints

### 1. Derive Bitcoin Address (Public)
Derives a Bitcoin address from an Ethereum address.
```sh
curl -X POST http://localhost:5555/derive_address \
  -H "Content-Type: application/json" \
  -d '{"ethereum_address": "0xF9F6608792F3efC3930D4083F52CEd39EB2F20D8"}'
```
Response:
```json
{
  "address": "bcrt1q..."
}
```

### 2. Sign Transaction (Protected)
Signs a Bitcoin transaction using keys derived from an Ethereum address. Requires an API key.
```sh
curl -X POST http://localhost:5555/sign_transaction \
  -H "Content-Type: application/json" \
  -d '{
    "ethereum_address": "742d35Cc6634C0532925a3b844Bc454e4438f44e",
    "inputs": [
      {
        "txid": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        "vout": 0,
        "amount": 200000000
      }
    ],
    "outputs": [
      {
        "address": "bcrt1pclxyszzcwv42fg54s4vk5vnxpmq4vgx65gxnhs5uvhkh5eg8t6qsntwfvu",
        "amount": 100000000
      }
    ]
  }'
```

Response:
```json
{
  "signed_tx": "02000000000101b2a1f0e9..."
}
```

## Implementation Details
- **Key Derivation**: The service uses a deterministic approach to derive Bitcoin keys from Ethereum addresses. The derivation path includes components of the Ethereum address split into 4-byte chunks to fit within BIP32's constraints.
- **Address Type**: All derived addresses are P2WPKH (Pay-to-Witness-Public-Key-Hash, SegWit) addresses, which are more efficient and have lower transaction fees.
- **Networks**: The service supports all Bitcoin networks (Regtest, Testnet, Signet, and Mainnet). The network affects the address format and network parameters.
- **Security**:
  - The master seed must be provided as an environment variable (`BIP32_SEED`).
  - Protected endpoints require an API key to be set via the `API_KEY` environment variable.
  - No direct access to private keys is exposed via the API.

## Notes:
- In a production environment, ensure the BIP32_SEED is securely generated and stored, and that it's kept private.
- The API does not validate that the transaction inputs can actually be spent. It's the caller's responsibility to ensure the provided inputs are valid and can be spent by the derived key.
- The service assumes all derived addresses are P2WPKH. If other address types are needed, the code would need to be modified
