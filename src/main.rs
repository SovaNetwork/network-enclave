use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use actix_web::{web, App, HttpResponse, HttpServer, Responder};

use clap::Parser;
use hex::FromHex;
use serde::{Deserialize, Serialize};

use tracing::{debug, error, info, warn};

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::hashes::{hash160, sha256, Hash, HashEngine};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};

const SOVA_ADDR_CONVERT_DOMAIN_TAG: &[u8] = b"sova:evm2btc:v1.0";

#[derive(Parser, Debug)]
#[command(about = "server that holds a BIP32 wallet with signing capabilities")]
struct Args {
    /// Host address to bind to
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Port to listen on
    #[arg(long, default_value = "5555")]
    port: u16,

    /// Bitcoin network to use (regtest, testnet, mainnet)
    #[arg(long, value_parser = parse_network, default_value = "regtest")]
    network: Network,

    /// Path to persist the address map
    #[arg(long, default_value = "./data/address_map.bin")]
    address_map_path: String,

    /// Logging level (error, warn, info, debug, trace)
    #[arg(long, default_value = "info")]
    log_level: String,
}

fn parse_network(s: &str) -> Result<Network, &'static str> {
    match s.to_lowercase().as_str() {
        "regtest" => Ok(Network::Regtest),
        "testnet" => Ok(Network::Testnet),
        "signet" => Ok(Network::Signet),
        "mainnet" => Ok(Network::Bitcoin),
        _ => Err("Invalid network. Use 'regtest', 'testnet', 'signet' or 'mainnet'"),
    }
}

struct SecureEnclave {
    network: Network,
    master_key: Xpriv,
    secp: Secp256k1<bitcoin::secp256k1::All>,
}

impl SecureEnclave {
    /// Generate new SecureEnclave master key
    pub fn new(seed: &[u8], network: Network) -> Result<Self, Box<dyn std::error::Error>> {
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
        // EXACT same logic as network code - hash with domain separation
        let mut engine = sha256::Hash::engine();
        engine.input(SOVA_ADDR_CONVERT_DOMAIN_TAG);
        engine.input(evm_address);
        let hash = sha256::Hash::from_engine(engine);
        let hash_bytes = hash.to_byte_array();

        // Create base path: m/44'/0' (same as network code sova_xpub derivation)
        let mut chunks = vec![
            ChildNumber::from_hardened_idx(44)?, // Purpose: BIP44
            ChildNumber::from_hardened_idx(0)?,  // Coin type: Bitcoin
        ];

        // Add 7 non-hardened levels from hash (matching network code exactly)
        for i in 0..7 {
            let chunk_start = i * 4;
            let chunk_bytes = &hash_bytes[chunk_start..chunk_start + 4];

            // Convert 4 bytes to u32 and mask to ensure non-hardened
            // MUST match network code masking
            let value = u32::from_be_bytes([
                chunk_bytes[0],
                chunk_bytes[1],
                chunk_bytes[2],
                chunk_bytes[3],
            ]) & 0x7FFFFFFF; // Clear MSB to ensure non-hardened

            chunks.push(ChildNumber::from(value));
        }

        Ok(DerivationPath::from(chunks))
    }

    /// Given an Ethereum address (20-byte array), derive the corresponding Bitcoin address
    pub fn derive_bitcoin_address(
        &self,
        evm_address: &[u8; 20],
    ) -> Result<Address, Box<dyn std::error::Error>> {
        // Derive to the ethereum xpub level (m/44'/0')
        let ethereum_path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(44)?,
            ChildNumber::from_hardened_idx(0)?,
        ]);
        let ethereum_xpriv = self.master_key.derive_priv(&self.secp, &ethereum_path)?;

        // Then get the hash-based derivation path
        let full_path = Self::evm_address_to_btc_derivation_path(evm_address)?;
        // Extract just the non-hardened part (skip m/44'/0')
        let child_path =
            DerivationPath::from(full_path.into_iter().skip(2).cloned().collect::<Vec<_>>());

        // Derive from ethereum xpriv using child path
        let child_key = ethereum_xpriv.derive_priv(&self.secp, &child_path)?;
        let public_key = PublicKey::new(child_key.private_key.public_key(&self.secp));

        Address::p2wpkh(&public_key, self.network).map_err(|e| e.into())
    }

    /// Sign all inputs of a transaction using the provided ethereum address for key derivation.
    /// The signing protocol uses a P2WPKH sig hash since all derived addresses are P2WPKH.
    /// This function assumes that the signer can spend all of the transaction inputs.
    pub fn sign_transaction(
        &self,
        inputs: Vec<(OutPoint, u64, [u8; 20])>,
        outputs: Vec<(Address, u64)>,
    ) -> Result<Transaction, Box<dyn std::error::Error>> {
        // Construct unsigned transaction
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: inputs
                .iter()
                .map(|(outpoint, _, _)| TxIn {
                    previous_output: *outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence(u32::MAX),
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

        // Derive ethereum xpriv once
        let ethereum_path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(44)?,
            ChildNumber::from_hardened_idx(0)?,
        ]);
        let ethereum_xpriv = self.master_key.derive_priv(&self.secp, &ethereum_path)?;

        for (input_index, (_outpoint, input_value, evm_addr)) in inputs.iter().enumerate() {
            let full_path = Self::evm_address_to_btc_derivation_path(evm_addr)?;
            let child_path =
                DerivationPath::from(full_path.into_iter().skip(2).cloned().collect::<Vec<_>>());

            let child_key = ethereum_xpriv.derive_priv(&self.secp, &child_path)?;
            let public_key = child_key.private_key.public_key(&self.secp);

            // Create P2WPKH script for this input
            let pubkey_hash = hash160::Hash::hash(&public_key.serialize());
            let wpubkey_hash = bitcoin::WPubkeyHash::from_raw_hash(pubkey_hash);
            let p2wpkh_script = ScriptBuf::new_p2wpkh(&wpubkey_hash);

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
            witness.push(public_key.serialize());

            tx.input[input_index].witness = witness;
        }

        Ok(tx)
    }

    pub fn get_sova_xpub(&self) -> Result<Xpub, Box<dyn std::error::Error>> {
        let ethereum_path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(44)?,
            ChildNumber::from_hardened_idx(0)?,
        ]);
        let ethereum_xpriv = self.master_key.derive_priv(&self.secp, &ethereum_path)?;
        Ok(Xpub::from_priv(&self.secp, &ethereum_xpriv))
    }
}

// API Helpers
pub fn eth_addr_to_bytes_slice(eth_addr: &str) -> Result<[u8; 20], Box<dyn std::error::Error>> {
    let eth_addr = match eth_addr.strip_prefix("0x") {
        Some(stripped) => stripped,
        None => eth_addr,
    };

    let eth_addr_array =
        <[u8; 20]>::from_hex(eth_addr).map_err(|e| format!("Invalid Ethereum address: {e}"))?;

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
    address: String,
}

#[derive(Deserialize)]
struct OutputData {
    address: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SignTransactionRequest {
    inputs: Vec<InputData>,
    outputs: Vec<OutputData>,
}

#[derive(Serialize)]
struct SignTransactionResponse {
    signed_tx: String,
}

#[derive(Serialize)]
struct EthereumXpubResponse {
    sova_xpub: String,
    network: String,
}

struct AppState {
    enclave: Arc<SecureEnclave>,
    api_key: String,
    address_map: RwLock<HashMap<String, [u8; 20]>>,
    address_map_path: PathBuf,
}

// API validation
fn check_api_key(req: &actix_web::HttpRequest, expected_key: &str) -> bool {
    if expected_key.is_empty() {
        return false;
    }

    match req.headers().get("X-API-Key") {
        Some(header_value) => match header_value.to_str() {
            Ok(key) => key == expected_key,
            Err(_) => false,
        },
        None => false,
    }
}

// API handlers
async fn derive_address(
    http_req: actix_web::HttpRequest,
    state: web::Data<AppState>,
    req: web::Json<DeriveAddressRequest>,
) -> impl Responder {
    if !check_api_key(&http_req, &state.api_key) {
        warn!(
            "Unauthorized derive_address attempt from {:?}",
            http_req.peer_addr()
        );
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Unauthorized"}));
    }

    let enclave = &state.enclave;
    let evm_addr_bytes = match eth_addr_to_bytes_slice(&req.evm_address) {
        Ok(addr) => addr,
        Err(e) => {
            return HttpResponse::BadRequest()
                .body(format!("Cannot convert EVM address to bytes: {e}"))
        }
    };

    match enclave.derive_bitcoin_address(&evm_addr_bytes) {
        Ok(address) => {
            debug!("Derived Bitcoin address: {:?}", address);
            let address_str = address.to_string();
            {
                let mut map = state.address_map.write().unwrap();
                map.insert(address_str.clone(), evm_addr_bytes);
                if let Ok(serialized) = bincode::serialize(&*map) {
                    let _ = std::fs::write(&state.address_map_path, serialized);
                }
            }
            HttpResponse::Ok().json(DeriveAddressResponse {
                address: address_str,
            })
        }
        Err(e) => {
            debug!("Error deriving Bitcoin address: {:?}", e);
            HttpResponse::InternalServerError().body(e.to_string())
        }
    }
}

async fn sign_transaction(
    req: actix_web::HttpRequest,
    state: web::Data<AppState>,
    tx_req: web::Json<SignTransactionRequest>,
) -> impl Responder {
    if !check_api_key(&req, &state.api_key) {
        warn!(
            "Unauthorized sign_transaction attempt from {:?}",
            req.peer_addr()
        );
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Unauthorized"}));
    }

    let enclave = &state.enclave;

    let inputs_res: Result<Vec<(OutPoint, u64, [u8; 20])>, String> = tx_req
        .inputs
        .iter()
        .map(|input| {
            let evm = {
                let map = state.address_map.read().unwrap();
                map.get(&input.address)
                    .cloned()
                    .ok_or_else(|| format!("Unknown address: {}", input.address))
            }?;

            Ok((
                OutPoint {
                    txid: Txid::from_str(&input.txid)
                        .map_err(|_| format!("Invalid txid: {}", input.txid))?,
                    vout: input.vout,
                },
                input.amount,
                evm,
            ))
        })
        .collect();

    let inputs = match inputs_res {
        Ok(i) => i,
        Err(e) => return HttpResponse::BadRequest().body(e),
    };

    let outputs: Result<Vec<(Address, u64)>, Box<dyn std::error::Error>> = tx_req
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
        Err(e) => return HttpResponse::BadRequest().body(format!("Invalid output: {e}")),
    };

    info!("Signing transaction with {} inputs", inputs.len());
    match enclave.sign_transaction(inputs, outputs) {
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

async fn get_sova_xpub(req: actix_web::HttpRequest, state: web::Data<AppState>) -> impl Responder {
    if !check_api_key(&req, &state.api_key) {
        warn!(
            "Unauthorized get_sova_xpub attempt from {:?}",
            req.peer_addr()
        );
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Unauthorized"}));
    }

    let enclave = &state.enclave;
    match enclave.get_sova_xpub() {
        Ok(sova_xpub) => HttpResponse::Ok().json(EthereumXpubResponse {
            sova_xpub: sova_xpub.to_string(),
            network: match enclave.network {
                Network::Bitcoin => "mainnet".to_string(),
                Network::Testnet => "testnet".to_string(),
                Network::Signet => "signet".to_string(),
                Network::Regtest => "regtest".to_string(),
                _ => format!("{:?}", enclave.network),
            },
        }),
        Err(e) => {
            error!("Failed to get ethereum xpub: {}", e);
            HttpResponse::InternalServerError().body(e.to_string())
        }
    }
}

async fn get_address_map(
    req: actix_web::HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    if !check_api_key(&req, &state.api_key) {
        warn!(
            "Unauthorized get_address_map attempt from {:?}",
            req.peer_addr()
        );
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Unauthorized"}));
    }

    let map = state.address_map.read().unwrap();
    match serde_json::to_string(&*map) {
        Ok(body) => HttpResponse::Ok().body(body),
        Err(e) => {
            error!("Failed to serialize address map: {}", e);
            HttpResponse::InternalServerError().body(e.to_string())
        }
    }
}

async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy"
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize the tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(&args.log_level)
        .init();

    info!("Starting enclave service...");

    let api_key = std::env::var("ENCLAVE_API_KEY").unwrap_or_default();
    if api_key.is_empty() {
        warn!("ENCLAVE_API_KEY environment variable is not set. Protected endpoints will reject requests.");
    }

    // Get seed from environment variable
    let seed = match std::env::var("BIP32_SEED") {
        Ok(seed_hex) => match hex::decode(&seed_hex) {
            Ok(seed) => seed,
            Err(e) => {
                error!("ERROR: Invalid hex-encoded seed in BIP32_SEED: {}", e);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid hex-encoded seed",
                ));
            }
        },
        Err(_) => {
            error!("ERROR: BIP32_SEED environment variable must be set");
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "BIP32_SEED environment variable not set",
            ));
        }
    };

    let enclave = match SecureEnclave::new(&seed, args.network) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            error!("ERROR: Failed to create secure enclave: {}", e);
            return Err(std::io::Error::other(e.to_string()));
        }
    };

    let map_path = PathBuf::from(&args.address_map_path);
    let address_map: HashMap<String, [u8; 20]> = match std::fs::read(&map_path) {
        Ok(bytes) => bincode::deserialize(&bytes).unwrap_or_default(),
        Err(_) => HashMap::new(),
    };

    let app_state = web::Data::new(AppState {
        enclave: enclave.clone(),
        api_key: api_key.clone(),
        address_map: RwLock::new(address_map),
        address_map_path: map_path,
    });

    let bind_addr = format!("{}:{}", args.host, args.port);
    info!("Binding to {}", bind_addr);

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .route("/derive_address", web::post().to(derive_address)) // protected
            .route("/health", web::get().to(health_check)) // unprotected
            .route("/sign_transaction", web::post().to(sign_transaction)) // protected
            .route("/sova_xpub", web::get().to(get_sova_xpub)) // protected
            .route("/address_map", web::get().to(get_address_map)) // protected
    })
    .bind(&bind_addr)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn create_test_enclave() -> SecureEnclave {
        // Use a fixed seed for deterministic testing
        let seed = [0u8; 32];
        SecureEnclave::new(&seed, Network::Regtest).unwrap()
    }

    #[test]
    fn test_address_map_persistence() {
        // Create a temporary directory for testing
        let temp_dir = TempDir::new().unwrap();
        let map_path = temp_dir.path().join("test_address_map.bin");

        // Test data
        let test_evm_addresses = vec![
            "0x1234567890123456789012345678901234567890",
            "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "0x9876543210987654321098765432109876543210",
        ];

        // Phase 1: Create initial address map and persist it
        {
            let enclave = create_test_enclave();
            let mut address_map = HashMap::new();

            // Derive addresses and build the map
            for evm_addr_str in &test_evm_addresses {
                let evm_addr_bytes = eth_addr_to_bytes_slice(evm_addr_str).unwrap();
                let btc_address = enclave.derive_bitcoin_address(&evm_addr_bytes).unwrap();
                address_map.insert(btc_address.to_string(), evm_addr_bytes);
            }

            // Simulate the persistence logic from the actual code
            let serialized = bincode::serialize(&address_map).unwrap();
            fs::write(&map_path, serialized).unwrap();

            // Verify the file was created
            assert!(map_path.exists());

            // Verify the map has the expected size
            assert_eq!(address_map.len(), test_evm_addresses.len());
        }

        // Phase 2: Load the persisted address map and verify it matches
        {
            let enclave = create_test_enclave();

            // Load the address map from disk (simulating service restart)
            let loaded_map: HashMap<String, [u8; 20]> = {
                let bytes = fs::read(&map_path).unwrap();
                bincode::deserialize(&bytes).unwrap()
            };

            // Verify the loaded map has the correct size
            assert_eq!(loaded_map.len(), test_evm_addresses.len());

            // Verify each address mapping is correct
            for evm_addr_str in &test_evm_addresses {
                let evm_addr_bytes = eth_addr_to_bytes_slice(evm_addr_str).unwrap();
                let expected_btc_address = enclave.derive_bitcoin_address(&evm_addr_bytes).unwrap();

                // Check that the Bitcoin address exists in the loaded map
                assert!(loaded_map.contains_key(&expected_btc_address.to_string()));

                // Check that the EVM address bytes match
                let stored_evm_bytes = loaded_map.get(&expected_btc_address.to_string()).unwrap();
                assert_eq!(*stored_evm_bytes, evm_addr_bytes);
            }
        }
    }
}
