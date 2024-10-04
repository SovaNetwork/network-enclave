# Corsa Enclave

Corsa enclave is a service that host the network master key and has various methods available for use the master key like deriving child keys and signing transactions.

## Getting Started

To set up and run the Corsa Enclave service, follow these steps:

### Prerequisites

Ensure you have the following installed on your machine:

- [Just](https://just.systems/) - A command runner
- Rust and Cargo

### Clone the Repository

First, clone the repository to your local machine:

```sh
git clone https://github.com/OnCorsa/corsa-enclave.git
cd corsa-enclave
```

### Build and Run the Service
Run the following commands to build and start the service:
```sh
just build
just run
```
The service will now be running at http://localhost:5555.

## Show me!

### Convert a Ethereum address to derived BTC address
```sh
curl -X POST http://localhost:5555/derive_address \
  -H "Content-Type: application/json" \
  -d '{
    "ethereum_address": "F9F6608792F3efC3930D4083F52CEd39EB2F20D8" 
  }'
{"address":"bcrt1qdqvts4mprnngm0jcn5r6q0arelty7kpdt3uvk6"}
```

### Sign a transaction with a given ethereum address
```sh
curl -X POST http://localhost:5555/sign_transaction \
  -H "Content-Type: application/json" \
  -d '{
    "ethereum_address": "742d35Cc6634C0532925a3b844Bc454e4438f44e",
    "inputs": [
      {
        "txid": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        "vout": 0,
        "value": 200000000
      }
    ],
    "outputs": [
      [
        "BCRT1QP5WFCQ48H6D63WYY9QZ0AWTPFQWWV4SM4GC9MC",
        100000000
      ]
    ]
  }'
{"signed_tx":"02000000000101b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a10000000000ffffffff0100e1f505000000001600140d1c9c02a7be9ba8b8842804feb961481ce6561b02473045022100bfc808079442fdb4f95ba0347d0ab1a2001f2426bd506461e323dd195a04bdfc02204cf8b1d3f67ed7d90f78de9c00c62123f641a412698a960e95a074586a54d762210231c69428e898cdce91bd3c82b32d052f842f0db39c08fd13c994f50ad38d4b8f00000000"}
```

### Get Bitcoin public key for Ethereum address
```sh
curl -X POST http://localhost:5555/get_public_key \
  -H "Content-Type: application/json" \
  -d '{
    "ethereum_address": "F9F6608792F3efC3930D4083F52CEd39EB2F20D8"
  }'
{"public_key":"03dcf2345096bf5d2d81f5810f68e477eb2629df9de98188c61c3e587935387f0c"}
```

## Notes:
Transaction signing is not a finalized design. There are limitations built into the current design.