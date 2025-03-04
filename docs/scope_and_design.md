## Network Signing

Overview: Network signing enables validators on the Sova Network to control Bitcoin assets through a secure, deterministic key derivation system. This infrastructure acts as a conduit for allowing smart contracts on the network to broadcast Bitcoin transactions.

*What is the Network Signing service?*
The network signing service (nicknamed: 'enclave') is a service which enables validators to send BTC assets controlled by the network to wallets outside the network. 

*Why is this needed?*
The Sova Networks needs a way to send UTXOs that are owned by smart contracts. Many smart contract protocols will utilize this network feature when a user wants to settle their tokens on Sova back into native BTC. An example of this is a DEX where a user swaps "Sova Dog Token" for BTC.

### Technical Requirements

1. Securely manage a root extended master private key.
2. Generate key shards to be used by validators in signing.
3. Provide high availability and resilience.

### Core Components

1. **Network Key Management**: 
   - Signing service holds a shared root network key that allows validators to interact with Bitcoin.

2. **Security Features**:
   - Protection against key theft through sharding and TEEs (Trusted Execution Environments).
   - Completely sealed execution environment which handles pk shard requests.
   - Multisignature schemes to ensure resilience against network failures.
   - Economic security through validator slashing conditions.
   - Defense in depth.

3. **Transaction Flow**:
   - Validators process Sova EVM transactions that interact with Bitcoin.
   - When network signing Bitcoin precompile is called, validators prepare a UTXO payload.
   - Validator requests a key shard to be used in signing the payload.
   - Validator signs the payload.
   - Signed transaction is broadcast to Bitcoin.

## Design Questions

### Decentralization
* What threshold signature scheme should we implement for the sharded key?
* What properties of this design enable decentralization at scale? Do parts of this design need to be decentralized progressively?
* What's the minimum viable decentralization for launch?
* What does operator onboarding look like?
* How does the network handle key rotation or recovery in a decentralized setting?

### Operational
* How can we ensure the integrity of the key shards during distribution?
* What monitoring systems should be put in place and what are they tuned to detect?
* What's the approach to disaster recovery?
* How does the network handle version upgrades of the signing service?

### Implementation
* What specific TEE frameworks are most appropriate for this application? Language?
* What existing multi-party computation or threshold signature libraries are used?
* What's our approach to auditing and verification? "Sting framework" for proving a subversion service. Side-channel attacks?
* How can we proactively test the security of the implementation?

### General
* What is the timeline for implementation and deployment?
* What are some alternative designs? Why are they inferior or not considered for this project?
* How can we demonstrate to investors and users this design can be trusted?
* What is the estimated cost for running the signing service? Can this cost be offloaded to the network somehow?


## Designing for an Evolving Network

### Centralized Network Signer (Phase 1)

For the beginning stages of the network, the signer responsibilities will be controlled by one service that takes signature requests and returns signed payloads.

Validators are responsible with determining signing context. The context consists of who the Bitcoin signer is and what UTXOs make up the signed transaction. The most straightforward way of accomplishing this is to deterministically convert all EVM addresses to BIP32 derivation paths.

For example:
```rust
pub fn derive_bitcoin_address(
   &self,
   evm_address: &[u8; 20],
) -> Result<Address, Box<dyn std::error::Error>> {
   let path = Self::evm_address_to_btc_derivation_path(evm_address)?;

   let child_key = self.master_key.derive_priv(&self.secp, &path)?;
   let public_key = PublicKey::new(child_key.private_key.public_key(&self.secp));

   Address::p2wpkh(&public_key, self.network).map_err(|e| e.into())
}
```

In order to know what UTXOs a EVM address can spend, the validators must all run an indexing service which they can query for this information.

When a protocol wants to pull native Bitcoin funds from a user, the user signs a transaction saying the recipient of the tx is the corresponding Sova smart contract public Bitcoin address. Then, when the smart contract is processing and pulling the funds from the user, they check they are the recipient and then broadcast the signed payload. Once the broadcast transaction confirms on Bitcoin, the smart contract (Sova Network) now owns that Bitcoin and has the ability to spend it via the network signing service. 

## Decentralized Network Signer (Phase X)

In a more mature version of the network, we cannot place this much trust and responsibility on a single service. For many reasons, the signing service must be decentralized and not be a single point of failure for the network.

The initial point of decentralizing this service will be to modify the signing service protocol so that anyone can run a signing service and be apart of a 'network' of signing services. This way if one signing service goes down, there is "defence in depth" and the network can continue processing signed payload requests.

In a network of signers, there is a fundamental change to a primary characteristic of the signing protocol. No single service can control the network private key; it must be 'shared' amongst the network of signers such that no signer knows the entire private key. Each signer may only know a shard of the private key, but signers can combine their shards to produce fully signed payloads for the network.

### Implementing Threshold Signatures

The plan is to implement a threshold signature scheme where m-of-n signers must participate to create a valid signature. This provides both security and availability:

1. **Security**: Even if up to (m-1) signers are compromised, the network key remains secure
2. **Availability**: The system continues functioning even if (n-m) signers are offline

For the signature scheme we will use ECDSA since it's directly compatible with Bitcoin signatures. The protocol will work as follows:

1. Each signer maintains its key share in a secure TEE
2. When a signature is required:
   - Validators independently verify the transaction request
   - Each participating signer produces a partial signature
   - A threshold of partial signatures are combined to form a complete signature
   - The complete signature is broadcast with the transaction

### Key Generation and Distribution

The initial key generation will be conducted through a secure ceremony:

1. A trusted setup process generates the master key and creates the shards
2. Each key shard is securely distributed to an independent signer
3. Signers store their shards in hardware-protected TEEs
4. The original master key is verifiably destroyed after distribution

As the network matures, we'll implement distributed key generation (DKG) protocols so that the master key never exists in complete form, even during the setup phase.

### Signer Selection and Rotation

To mitigate centralization risks:

1. **Diverse Selection**: Signers should be distributed across:
   - Different geographic regions
   - Various legal jurisdictions
   - Multiple hardware vendors and TEE technologies

2. **Periodic Rotation**: The signing set will rotate periodically to:
   - Prevent collusion
   - Allow for key refreshing without reconstructing the master key
   - Accommodate new signers as the network grows

3. **Economic Incentives**: Signers will receive compensation for:
   - Maintaining high availability
   - Responding quickly to signing requests
   - Properly following the security protocol

### Governance and Security Upgrades

The signer network will need governance mechanisms for:

1. Adding or removing signers
2. Changing the threshold parameters
3. Upgrading the signing protocol
4. Responding to security incidents

This governance will initially be controlled by the project team but will gradually transition to a decentralized governance process as the network matures.