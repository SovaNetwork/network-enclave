use std::str::FromStr;
use std::sync::Arc;

use hex::FromHex;

use serde::{Deserialize, Serialize};

use clap::Parser;

use actix_web::{web, App, HttpResponse, HttpServer, Responder};

use bitcoin::hashes::{hash160, Hash};

use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Host address to bind to
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Port to listen on
    #[arg(long, default_value = "5555")]
    port: u16,

    /// Hex-encoded seed for key generation
    #[arg(long, default_value = "000102030405060708090a0b0c0d0e0f")]
    seed: String,
}

struct SecureEnclave {
    network: Network,
    master_key: Xpriv,
    secp: Secp256k1<bitcoin::secp256k1::All>,
}

impl SecureEnclave {
    /// Generate new SecureEnclave master key
    pub fn new(seed: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let network = Network::Regtest; // update for testnet or mainnet
        let master_key = Xpriv::new_master(network, seed)?;

        Ok(SecureEnclave {
            network,
            master_key,
            secp: Secp256k1::new(),
        })
    }

    /// Derive the corresponding bip32 derivation path from the evm address
    fn evm_address_to_btc_derivation_path(
        evm_address: &[u8; 20],
    ) -> Result<DerivationPath, Box<dyn std::error::Error>> {
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(44)?, // Purpose: BIP44
            ChildNumber::from_hardened_idx(0)?,  // Coin type: Bitcoin
            // split into 4 byte chunks to fit the entire eth address
            ChildNumber::from(
                (evm_address[0] as u32) << 24
                    | (evm_address[1] as u32) << 16
                    | (evm_address[2] as u32) << 8
                    | evm_address[3] as u32,
            ), // uint32, 4 bytes
            ChildNumber::from(
                (evm_address[4] as u32) << 24
                    | (evm_address[5] as u32) << 16
                    | (evm_address[6] as u32) << 8
                    | evm_address[7] as u32,
            ), // uint32, 4 bytes
            ChildNumber::from(
                (evm_address[8] as u32) << 24
                    | (evm_address[9] as u32) << 16
                    | (evm_address[10] as u32) << 8
                    | evm_address[11] as u32,
            ), // uint32, 4 bytes
            ChildNumber::from(
                (evm_address[12] as u32) << 24
                    | (evm_address[13] as u32) << 16
                    | (evm_address[14] as u32) << 8
                    | evm_address[15] as u32,
            ), // uint32, 4 bytes
            ChildNumber::from(
                (evm_address[16] as u32) << 24
                    | (evm_address[17] as u32) << 16
                    | (evm_address[18] as u32) << 8
                    | evm_address[19] as u32,
            ), // uint32, 4 bytes
        ]); // uint160 (20 bytes) = ethereum address
        Ok(path)
    }

    /// Given an Ethereum address (20-byte array), derive the corresponding Bitcoin address
    pub fn derive_bitcoin_address(
        &self,
        evm_address: &[u8; 20],
    ) -> Result<Address, Box<dyn std::error::Error>> {
        let path = Self::evm_address_to_btc_derivation_path(evm_address)?;

        let child_key = self.master_key.derive_priv(&self.secp, &path)?;
        let public_key = PublicKey::new(child_key.private_key.public_key(&self.secp));

        Address::p2wpkh(&public_key, self.network).map_err(|e| e.into())
    }

    /// Sign all inputs of a transaction using the provided ethereum address for key derivation.
    /// The signing protocol uses a P2WPKH sig hash since all derived addresses are P2WPKH.
    /// This function assumes that the signer can spend all of the transaction inputs.
    pub fn sign_transaction(
        &self,
        evm_address: &[u8; 20],
        inputs: Vec<(OutPoint, u64)>,
        outputs: Vec<(Address, u64)>,
    ) -> Result<Transaction, Box<dyn std::error::Error>> {
        let path = Self::evm_address_to_btc_derivation_path(evm_address)?;
        let child_key = self.master_key.derive_priv(&self.secp, &path)?;
        let public_key = child_key.private_key.public_key(&self.secp);

        // Create P2WPKH script
        let pubkey_hash = hash160::Hash::hash(&public_key.serialize());
        let wpubkey_hash = bitcoin::WPubkeyHash::from_raw_hash(pubkey_hash);
        let p2wpkh_script = ScriptBuf::new_p2wpkh(&wpubkey_hash);

        // Construct unsigned transaction
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: inputs
                .iter()
                .map(|(outpoint, _)| TxIn {
                    previous_output: *outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence(std::u32::MAX),
                    witness: Witness::default(),
                })
                .collect(),
            output: outputs
                .iter()
                .map(|(address, amount)| TxOut {
                    value: Amount::from_sat(*amount),
                    script_pubkey: address.script_pubkey(),
                })
                .collect(),
        };

        for (input_index, (_outpoint, input_value)) in inputs.iter().enumerate() {
            let sighash = SighashCache::new(&tx).p2wpkh_signature_hash(
                input_index,
                &p2wpkh_script,
                Amount::from_sat(*input_value),
                EcdsaSighashType::All,
            )?;

            let message = Message::from_digest_slice(sighash.as_ref())?;
            let signature = self.secp.sign_ecdsa(
                &message,
                &child_key.private_key.keypair(&self.secp).secret_key(),
            );

            let mut signature_with_hashtype = signature.serialize_der().to_vec();
            signature_with_hashtype.push(EcdsaSighashType::All.to_u32() as u8);

            let mut witness = Witness::default();
            witness.push(signature_with_hashtype);
            witness.push(child_key.private_key.public_key(&self.secp).serialize());

            tx.input[input_index].witness = witness;
        }

        Ok(tx)
    }

    // Given an EVM address, derive the corresponding Bitcoin public key
    pub fn get_btc_public_key(
        &self,
        evm_address: &[u8; 20],
    ) -> Result<PublicKey, Box<dyn std::error::Error>> {
        let path = Self::evm_address_to_btc_derivation_path(evm_address)?;
        let child_key = self.master_key.derive_priv(&self.secp, &path)?;

        Ok(PublicKey::new(child_key.private_key.public_key(&self.secp)))
    }
}

// API Helpers
pub fn eth_addr_to_bytes_slice(eth_addr: &str) -> Result<[u8; 20], Box<dyn std::error::Error>> {
    let eth_addr = match eth_addr.strip_prefix("0x") {
        Some(stripped) => stripped,
        None => eth_addr,
    };

    let eth_addr_array =
        <[u8; 20]>::from_hex(eth_addr).map_err(|e| format!("Invalid Ethereum address: {}", e))?;

    Ok(eth_addr_array)
}

// API structs
#[derive(Deserialize)]
struct DeriveAddressRequest {
    evm_address: String,
}

#[derive(Serialize)]
struct DeriveAddressResponse {
    address: String,
}

#[derive(Deserialize)]
struct InputData {
    txid: String,
    vout: u32,
    amount: u64,
}

#[derive(Deserialize)]
struct OutputData {
    address: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SignTransactionRequest {
    evm_address: String,
    inputs: Vec<InputData>,
    outputs: Vec<OutputData>,
}

#[derive(Serialize)]
struct SignTransactionResponse {
    signed_tx: String,
}

#[derive(Deserialize)]
struct GetPublicKeyRequest {
    evm_address: String,
}

#[derive(Serialize)]
struct GetPublicKeyResponse {
    public_key: String,
}

// API handlers
async fn derive_address(
    enclave: web::Data<Arc<SecureEnclave>>,
    req: web::Json<DeriveAddressRequest>,
) -> impl Responder {
    let evm_addr_bytes = match eth_addr_to_bytes_slice(&req.evm_address) {
        Ok(addr) => addr,
        Err(e) => {
            return HttpResponse::BadRequest()
                .body(format!("Cannot convert EVM address to bytes: {}", e))
        }
    };

    match enclave.derive_bitcoin_address(&evm_addr_bytes) {
        Ok(address) => {
            debug!("Derived Bitcoin address: {:?}", address);
            HttpResponse::Ok().json(DeriveAddressResponse {
                address: address.to_string(),
            })
        }
        Err(e) => {
            debug!("Error deriving Bitcoin address: {:?}", e);
            HttpResponse::InternalServerError().body(e.to_string())
        }
    }
}

async fn sign_transaction(
    enclave: web::Data<Arc<SecureEnclave>>,
    req: web::Json<SignTransactionRequest>,
) -> impl Responder {
    let evm_addr_bytes = match eth_addr_to_bytes_slice(&req.evm_address) {
        Ok(addr) => addr,
        Err(e) => {
            return HttpResponse::BadRequest()
                .body(format!("Cannot convert Ethereum address to bytes: {}", e))
        }
    };

    let inputs: Vec<(OutPoint, u64)> = req
        .inputs
        .iter()
        .map(|input| {
            (
                OutPoint {
                    txid: Txid::from_str(&input.txid).expect("Invalid txid"),
                    vout: input.vout,
                },
                input.amount,
            )
        })
        .collect();

    let outputs: Result<Vec<(Address, u64)>, Box<dyn std::error::Error>> = req
        .outputs
        .iter()
        .map(|output| {
            Address::from_str(&output.address)
                .map_err(|e| e.into())
                .and_then(|addr| addr.require_network(enclave.network).map_err(|e| e.into()))
                .map(|addr| (addr, output.amount))
        })
        .collect();

    let outputs = match outputs {
        Ok(o) => o,
        Err(e) => return HttpResponse::BadRequest().body(format!("Invalid output: {}", e)),
    };

    match enclave.sign_transaction(&evm_addr_bytes, inputs, outputs) {
        Ok(signed_tx) => {
            debug!("Signed transaction: {:?}", signed_tx);
            HttpResponse::Ok().json(SignTransactionResponse {
                signed_tx: hex::encode(bitcoin::consensus::serialize(&signed_tx)),
            })
        }
        Err(e) => {
            debug!("Error signing transaction: {:?}", e);
            HttpResponse::InternalServerError().body(e.to_string())
        }
    }
}

async fn get_btc_public_key(
    enclave: web::Data<Arc<SecureEnclave>>,
    req: web::Json<GetPublicKeyRequest>,
) -> impl Responder {
    let evm_addr_bytes = match eth_addr_to_bytes_slice(&req.evm_address) {
        Ok(addr) => addr,
        Err(e) => {
            return HttpResponse::BadRequest()
                .body(format!("Cannot convert Ethereum address to bytes: {}", e))
        }
    };

    match enclave.get_btc_public_key(&evm_addr_bytes) {
        Ok(public_key) => {
            debug!("Derived public key: {:?}", public_key);
            HttpResponse::Ok().json(GetPublicKeyResponse {
                public_key: public_key.to_string(),
            })
        }
        Err(e) => {
            debug!("Error deriving public key: {:?}", e);
            HttpResponse::InternalServerError().body(e.to_string())
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize the tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    info!("Starting enclave service...");

    // Use seed from CLI args
    let seed = hex::decode(&args.seed).expect("Invalid hex-encoded seed");
    let enclave = Arc::new(SecureEnclave::new(&seed).unwrap());
    let enclave_data = web::Data::new(enclave);

    let bind_addr = format!("{}:{}", args.host, args.port);
    info!("Binding to {}", bind_addr);

    HttpServer::new(move || {
        App::new()
            .app_data(enclave_data.clone())
            .route("/derive_address", web::post().to(derive_address))
            .route("/sign_transaction", web::post().to(sign_transaction))
            .route("/get_public_key", web::post().to(get_btc_public_key))
    })
    .bind(&bind_addr)?
    .run()
    .await
}
