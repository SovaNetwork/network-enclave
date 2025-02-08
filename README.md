# Network Enclave

Network Enclave is a bitcoin signing service that hosts the network master key and provides various methods for use, such as deriving child keys and signing transactions. This service uses Bitcoin's BIP32 hierarchical deterministic wallets to derive Bitcoin addresses and keys from Ethereum addresses.

## Features

- Derive Bitcoin addresses from Ethereum addresses
- Sign Bitcoin transactions using keys derived from Ethereum addresses
- Retrieve public keys corresponding to Ethereum addresses

## Getting Started

To set up and run the enclave service, follow these steps:

### Prerequisites

Ensure you have the following installed on your machine:

- Rust and Cargo
- [Just](https://just.systems/) - A command runner

### Clone the Repository

First, clone the repository to your local machine:

```sh
git clone https://github.com/OnCorsa/network-enclave.git
cd network-enclave
```

### Build and Run the Service
Run the following command to build and start the service:
```sh
cargo run
```
or if you have Just installed:

```sh
just run
```
The service will now be running at http://localhost:5555.

## API Endpoints

### 1. Derive Bitcoin Address
Convert a Ethereum address to derived BTC address
```sh
curl -X POST http://localhost:5555/derive_address \
  -H "Content-Type: application/json" \
  -d '{"ethereum_address": "0xF9F6608792F3efC3930D4083F52CEd39EB2F20D8"}'
```

### 2. Sign Transaction
Sign a transaction with a given ethereum address
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

### 3. Get Public Key 
Get Bitcoin public key for Ethereum address
```sh
curl -X POST http://localhost:5555/get_public_key \
  -H "Content-Type: application/json" \
  -d '{"ethereum_address": "0xF9F6608792F3efC3930D4083F52CEd39EB2F20D8"}'
```

## Implementation Details
- The service uses Bitcoin's Regtest network by default. Update the network variable in the SecureEnclave::new() method to use Testnet or Mainnet.
- The master key is currently initialized with a hardcoded seed. In production, this should be securely provided or generated.
- The derivation path for Bitcoin keys is based on the Ethereum address, allowing deterministic derivation of Bitcoin keys from Ethereum addresses. The highest index for each derivation level is uint32, this is why there are 5 derivation levels when converting.
- All derived addresses are P2WPKH (Pay-to-Witness-Public-Key-Hash) addresses.
- The address derivation and transaction signing mechanisms uses P2WPKH (SegWit) addresses and signing, which is more efficient and cheaper in terms of transaction fees.

## Notes:
- The current implementation uses a hardcoded seed for the master key. In a real-world scenario, this seed should be securely generated and stored.
- Transaction signing does not validate that the signer can actually spend the inputs. It signs whatever input is provided. It is the responsibility of the calling service to ensure the provided inputs can be spent.
- The service uses tracing for logging. You can adjust the log level by setting the RUST_LOG environment variable.
