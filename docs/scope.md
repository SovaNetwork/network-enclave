## Network Signing Overview

Network signing enables validators on the Sova Network to control Bitcoin assets through a secure, deterministic key derivation system. This infrastructure acts as a conduit for allowing smart contracts on the network to broadcast Bitcoin transactions.

### Technical Requirements

1. Securely manage a root extended master private key
2. Generate deterministic keys for smart contracts
3. Sign Bitcoin transaction inputs
4. Provide high availability and resilience

### Core Components

1. **Network Key Management**: 
   - Signing service holds a shared root network key that allows validators to interact with Bitcoin.

2. **Security Features**:
   - Protection against key theft through sharding and TEEs (Trusted Execution Environments).
   - Completely sealed execution environment which handles pk shard requests.
   - Multisignature schemes to ensure resilience against network failures
   - Economic security through validator slashing conditions

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
* What specific TEE frameworks are most appropriate for this application?
* What programming language and frameworks are used?
* What existing multi-party computation or threshold signature libraries are used?
* What's our approach to auditing and verification?
* What protection mechanisms can we implement to protect us against side-channel attacks?
* How can we test the security of the implementation?

### General
* What is the timeline for implementation and deployment?
* What are some alternative designs? Why are they inferior or not considered for this project?
* How can we demonstrate to investors and users this design can be trusted?
* What is the estimated cost for running the signing service? Can this cost be offloaded to the network somehow?