# Corsa Enclave

Corsa enclave is a service that hosts the network master key and has various methods available for use, like deriving child keys and signing transactions.

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
Run the following command to build and start the service:
```sh
just run
```
The service will now be running at http://localhost:5555.

## Show me!

### Convert a Ethereum address to derived BTC address
```sh
curl -X POST http://localhost:5555/derive_address \
  -H "Content-Type: application/json" \
  -d '{"ethereum_address": "0xF9F6608792F3efC3930D4083F52CEd39EB2F20D8"}'
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

### Get Bitcoin public key for Ethereum address
```sh
curl -X POST http://localhost:5555/get_public_key \
  -H "Content-Type: application/json" \
  -d '{"ethereum_address": "0xF9F6608792F3efC3930D4083F52CEd39EB2F20D8"}'
```

## Notes:
Transaction signing does not validate that the signer can actually spend the inputs. It just dumbly signs whatever input is provided. It is up to the calling service to ensure the data provided can be spent.
