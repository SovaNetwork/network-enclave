# Network Enclave

A Bitcoin signing service used by the Sova Network that hosts the network's master key and provides APIs for derivation of Bitcoin addresses from EVM addresses and signing of Bitcoin transactions. This service uses Bitcoin's BIP32 hierarchical deterministic wallets to deterministically derive Bitcoin addresses and keys from EVM addresses using a cryptographically secure hash-based approach.

## Features

- Derive Bitcoin addresses from EVM addresses
- Sign Bitcoin transactions
- Support for multiple Bitcoin networks (Regtest, Testnet, Signet, Mainnet)
- Secure API key authentication for protected endpoints
- Domain-separated hashing to prevent cross-protocol attacks
- Persistent address mapping saved to disk for easy restarts
- Automatically creates the address mapping storage directory (`./data/`) if it doesn't exist
- Collision-resistant address derivation with 2^108 security level

## Getting Started

### Prerequisites

Ensure you have the following installed on your machine:

- Rust and Cargo
- [Just](https://just.systems/) - A command runner (optional, for convenience)

### Clone the Repository

First, clone the repository to your local machine:

```sh
git clone https://github.com/sovanetwork/network-enclave.git
cd network-enclave
```

### Environment Variables

The service requires the following environment variables:

- `BIP32_SEED` - Hex-encoded seed for the BIP32 master key (mandatory)
- `ENCLAVE_API_KEY` - API key for protected endpoints (if not set, protected endpoints will reject requests)
- `RUST_LOG` - Log level (e.g., info, debug, warn) - defaults to info

### Build and Run
```sh
# build
cargo build --release

# run
BIP32_SEED=000102030405060708090a0b0c0d0e0f ENCLAVE_API_KEY=api_key_here cargo run --release
```
or if you have Just installed:

```sh
BIP32_SEED=000102030405060708090a0b0c0d0e0f ENCLAVE_API_KEY=api_key_here just run
```

### Command-Line Arguments

The service supports the following command-line arguments:

- `--host` - Host address to bind to (default: 127.0.0.1)
- `--port` - Port to listen on (default: 5555)
- `--network` - Bitcoin network to use (options: regtest, testnet, signet, mainnet; default: regtest)
- `--log-level` - Logging level (options: error, warn, info, debug, trace; default: info)
- `--address-map-path` - File path for persisting the address map (default: ./data/address_map.bin)

Example with custom arguments:
```sh
BIP32_SEED=000102030405060708090a0b0c0d0e0f ENCLAVE_API_KEY=api_key_here cargo run --release -- --host 0.0.0.0 --port 8080 --network regtest --log-level debug
```

## API Endpoints

### 1. Health Check (Unprotected)
Basic health check endpoint that doesn't require authentication.
```sh
curl http://localhost:5555/health
```
Response:
```json
{
  "status": "healthy"
}
```

### 2. Derive Bitcoin Address (Protected)
Derives a Bitcoin address from an EVM address. Requires the `X-API-Key` header.
```sh
curl -X POST http://localhost:5555/derive_address \
  -H "Content-Type: application/json" \
  -H "X-API-Key: api_key_here" \
  -d '{"evm_address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"}'
```
Response:
```json
{
  "address": "bcrt1q..."
}
```

### 3. Get EVM Extended Public Key (Protected)
Returns the EVM-level extended public key (m/44'/0') for use by network nodes. This is the public key used for deterministic address derivation.
```sh
curl -X GET http://localhost:5555/sova_xpub \
  -H "X-API-Key: api_key_here"
```
Response:
```json
{
  "sova_xpub": "xpub6D4BDPcP2GT9...",
  "network": "regtest"
}
```

### 4. Sign Transaction (Protected)
Signs a Bitcoin transaction using keys derived from EVM addresses. The service must have previously derived the addresses via `/derive_address` to maintain the mapping between Bitcoin addresses and EVM addresses.
```sh
curl -X POST http://localhost:5555/sign_transaction \
  -H "Content-Type: application/json" \
  -H "X-API-Key: api_key_here" \
  -d '{
    "inputs": [
      {
        "txid": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        "vout": 0,
        "amount": 200000000,
        "address": "bcrt1q..."
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
### 5. Get Address Map (Protected)
Returns the current mapping of Bitcoin addresses to their source EVM addresses.
```sh
curl -X GET http://localhost:5555/address_map \
  -H "X-API-Key: api_key_here"
```
Response:
```json
{"bcrt1q...":"0xf39f..."}
```

## Implementation Details

### Key Derivation Algorithm
The service uses a cryptographically secure hash-based approach to derive Bitcoin keys from EVM addresses:

1. **Domain Separation**: Each EVM address is hashed with a domain tag to prevent cross-protocol attacks
2. **SHA256 Hashing**: The combination of domain tag + EVM address is hashed with SHA256
3. **BIP32 Path Generation**: The 256-bit hash is split into 7 chunks of 4 bytes each, creating a 9-level derivation path:
   - `m/44'/0'` - Base EVM extended key path (hardened)
   - 7 additional non-hardened levels derived from hash chunks

### Security Properties
- **Collision Resistance**: ~2^108 operations needed to find two EVM addresses that map to the same Bitcoin address
- **Entropy Utilization**: 217 out of 256 bits (85%) of hash entropy used in derivation
- **Domain Separation**: Prevents attacks from other systems using the same EVM addresses
- **Non-hardened Derivation**: Allows public key derivation without private key access

### Technical Specifications
- **Address Type**: All derived addresses are P2WPKH (Pay-to-Witness-Public-Key-Hash, SegWit) addresses
- **Networks**: Supports all Bitcoin networks (Regtest, Testnet, Signet, and Mainnet)
- **Derivation Path**: `m/44'/0'/hash_chunk_1/hash_chunk_2/.../hash_chunk_7` where hash chunks are derived from SHA256(domain_tag || EVM_address)
- **Address Map Persistence**: Address mappings are saved to disk (see `--address-map-path`); ensure the file persists across restarts

### Security Considerations
- **Master Seed Security**: The `BIP32_SEED` must be cryptographically secure (256+ bits of entropy) and kept private
- **API Key Protection**: Use strong API keys and ensure HTTPS in production
- **Network Validation**: All output addresses are validated against the specified Bitcoin network

### Integration with Sova Network
1. **Setup**: Deploy the service and get the extended public key via `/sova_xpub` route
3. **Address Derivation**: Nodes can derive Bitcoin addresses locally using an extended public key (`SOVA_DERIVATION_XPUB`)
4. **Transaction Signing**: When spending is needed, the sequencer will call the enclave's `/sign_transaction` endpoint

### Limitations
- **Transaction Validation**: The API does not validate that transaction inputs can actually be spent - caller must ensure inputs are valid
- **Address Type Constraints**: Only P2WPKH addresses are currently supported
