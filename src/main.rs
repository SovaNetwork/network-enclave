use std::sync::Arc;
use std::str::FromStr;

use actix_web::{web, App, HttpServer, Responder, HttpResponse};

use serde::{Deserialize, Serialize};

use bitcoin::{Address, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin::bip32::{Xpriv, DerivationPath, ChildNumber};
use bitcoin::sighash::{SighashCache, EcdsaSighashType};
use bitcoin::secp256k1::{Secp256k1, Message};
use bitcoin::Amount;

struct SecureEnclave {
    network: Network,
    master_key: Xpriv,
    secp: Secp256k1<bitcoin::secp256k1::All>,
}

impl SecureEnclave {
    /// generate new SecureEnclave master key
    pub fn new(seed: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let secp = Secp256k1::new();
        let network = Network::Regtest;  // update for testnet or mainnet
        let master_key = Xpriv::new_master(network, seed)?;

        Ok(SecureEnclave {
            network,
            master_key,
            secp,
        })
    }

    /// Given an Ethereum address (as a 20-byte array), derive the corresponding bip32 derivation path
    fn ethereum_to_derivation_path(ethereum_address: &[u8; 20]) -> Result<DerivationPath, Box<dyn std::error::Error>> {
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(44)?,  // Purpose: BIP44
            ChildNumber::from_hardened_idx(0)?,   // Coin type: Bitcoin
            // split into 4 byte chunks to fit the entire eth address
            ChildNumber::from((ethereum_address[0] as u32) << 24 | (ethereum_address[1] as u32) << 16 | (ethereum_address[2] as u32) << 8 | ethereum_address[3] as u32), // uint32, 4 bytes
            ChildNumber::from((ethereum_address[4] as u32) << 24 | (ethereum_address[5] as u32) << 16 | (ethereum_address[6] as u32) << 8 | ethereum_address[7] as u32), // uint32, 4 bytes
            ChildNumber::from((ethereum_address[8] as u32) << 24 | (ethereum_address[9] as u32) << 16 | (ethereum_address[10] as u32) << 8 | ethereum_address[11] as u32), // uint32, 4 bytes
            ChildNumber::from((ethereum_address[12] as u32) << 24 | (ethereum_address[13] as u32) << 16 | (ethereum_address[14] as u32) << 8 | ethereum_address[15] as u32), // uint32, 4 bytes
            ChildNumber::from((ethereum_address[16] as u32) << 24 | (ethereum_address[17] as u32) << 16 | (ethereum_address[18] as u32) << 8 | ethereum_address[19] as u32) // uint32, 4 bytes
        ]); // uint160 (20 bytes) = ethereum address
        Ok(path)
    }

    /// Given an Ethereum address (as a 20-byte array), derive the corresponding Bitcoin address
    pub fn derive_bitcoin_address(&self, ethereum_address: &[u8; 20]) -> Result<Address, Box<dyn std::error::Error>> {
        let path = Self::ethereum_to_derivation_path(ethereum_address)?;
        
        let child_key = self.master_key.derive_priv(&self.secp, &path)?;
        let public_key = PublicKey::new(child_key.private_key.public_key(&self.secp));
        Address::p2wpkh(&public_key, self.network).map_err(|e| e.into())
    }

    /// Sign all inputs of a transaction using the provided ethereum address for key derivation.
    /// Uses Bitcoin SegWit protocol for signing P2WPKH inputs.
    /// Assumes that the signer can spend all of the transaction inputs.
    pub fn sign_transaction(
        &self,
        ethereum_address: &[u8; 20],
        inputs: Vec<(OutPoint, u64)>,
        outputs: Vec<(Address, u64)>
    ) -> Result<Transaction, Box<dyn std::error::Error>> {
        let path = Self::ethereum_to_derivation_path(ethereum_address)?;
        let child_key = self.master_key.derive_priv(&self.secp, &path)?;
        
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: inputs.iter().map(|(outpoint, _)| TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence(std::u32::MAX),
                witness: Witness::default(),
            }).collect(),
            output: outputs.iter().map(|(address, value)| TxOut {
                value: Amount::from_sat(*value),
                script_pubkey: address.script_pubkey(),
            }).collect(),
        };

        for (input_index, (_, input_value)) in inputs.iter().enumerate() {
            let sighash = SighashCache::new(&tx).p2wsh_signature_hash(
                input_index,
                &bitcoin::Script::new(),
                Amount::from_sat(*input_value),
                EcdsaSighashType::All
            )?;
            
            let message = Message::from_digest_slice(sighash.as_ref())?;
            let signature = self.secp.sign_ecdsa(&message, &child_key.private_key.keypair(&self.secp).secret_key());
            
            // Construct the witness stack
            let mut witness = Witness::default();
            witness.push(signature.serialize_der().to_vec());
            witness.push(child_key.private_key.public_key(&self.secp).serialize());
            
            // Add the witness to the transaction
            tx.input[input_index].witness = witness;
        }

        Ok(tx)
    }

    pub fn get_public_key(&self, ethereum_address: &[u8; 20]) -> Result<PublicKey, Box<dyn std::error::Error>> {
        let path = Self::ethereum_to_derivation_path(ethereum_address)?;
        
        let child_key = self.master_key.derive_priv(&self.secp, &path)?;
        Ok(PublicKey::new(child_key.private_key.public_key(&self.secp)))
    }
}

// Custom Deserialize implementation for OutPoint
#[derive(Deserialize, Clone)]
struct OutPointHelper {
    txid: String,
    vout: u32,
}

impl From<OutPointHelper> for OutPoint {
    fn from(helper: OutPointHelper) -> Self {
        OutPoint {
            txid: Txid::from_str(&helper.txid).expect("Invalid txid"),
            vout: helper.vout,
        }
    }
}

#[derive(Deserialize)]
struct InputData {
    txid: String,
    vout: u32,
    value: u64,
}

// API structs
#[derive(Deserialize)]
struct DeriveAddressRequest {
    ethereum_address: String,
}

#[derive(Serialize)]
struct DeriveAddressResponse {
    address: String,
}

#[derive(Deserialize)]
struct SignTransactionRequest {
    ethereum_address: String,
    inputs: Vec<InputData>,
    outputs: Vec<(String, u64)>,
}

#[derive(Serialize)]
struct SignTransactionResponse {
    signed_tx: String,
}

#[derive(Deserialize)]
struct GetPublicKeyRequest {
    ethereum_address: String,
}

#[derive(Serialize)]
struct GetPublicKeyResponse {
    public_key: String,
}

// API handlers
async fn derive_address(enclave: web::Data<Arc<SecureEnclave>>, req: web::Json<DeriveAddressRequest>) -> impl Responder {
    let ethereum_address = match hex::decode(&req.ethereum_address) {
        Ok(addr) => addr,
        Err(e) => return HttpResponse::BadRequest().body(format!("Invalid Ethereum address: {}", e)),
    };
    
    if ethereum_address.len() != 20 {
        return HttpResponse::BadRequest().body("Ethereum address must be 20 bytes");
    }

    let mut eth_addr_array = [0u8; 20];
    eth_addr_array.copy_from_slice(&ethereum_address);

    match enclave.derive_bitcoin_address(&eth_addr_array) {
        Ok(address) => HttpResponse::Ok().json(DeriveAddressResponse {
            address: address.to_string(),
        }),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

async fn sign_transaction(enclave: web::Data<Arc<SecureEnclave>>, req: web::Json<SignTransactionRequest>) -> impl Responder {
    let ethereum_address = match hex::decode(&req.ethereum_address) {
        Ok(addr) => addr,
        Err(e) => return HttpResponse::BadRequest().body(format!("Invalid Ethereum address: {}", e)),
    };
    
    if ethereum_address.len() != 20 {
        return HttpResponse::BadRequest().body("Ethereum address must be 20 bytes");
    }

    let mut eth_addr_array = [0u8; 20];
    eth_addr_array.copy_from_slice(&ethereum_address);

    let inputs: Vec<(OutPoint, u64)> = req.inputs.iter()
        .map(|input| (
            OutPoint {
                txid: Txid::from_str(&input.txid).expect("Invalid txid"),
                vout: input.vout,
            },
            input.value
        ))
        .collect();

    let outputs: Result<Vec<(Address, u64)>, String> = req.outputs.iter()
        .map(|(addr_str, value)| {
            match Address::from_str(addr_str) {
                Ok(addr) => {
                    if *addr.network() == enclave.network {
                        Ok((addr.assume_checked(), *value))
                    } else {
                        Err(format!("Address network mismatch: address network is {:?}, enclave network is {:?}", addr.network(), enclave.network))
                    }
                },
                Err(e) => Err(format!("Invalid output address '{}': {}", addr_str, e)),
            }
        })
        .collect();

    let outputs = match outputs {
        Ok(o) => o,
        Err(e) => return HttpResponse::BadRequest().body(e),
    };

    match enclave.sign_transaction(&eth_addr_array, inputs, outputs) {
        Ok(signed_tx) => HttpResponse::Ok().json(SignTransactionResponse {
            signed_tx: hex::encode(bitcoin::consensus::serialize(&signed_tx)),
        }),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

async fn get_public_key(enclave: web::Data<Arc<SecureEnclave>>, req: web::Json<GetPublicKeyRequest>) -> impl Responder {
    let ethereum_address = match hex::decode(&req.ethereum_address) {
        Ok(addr) => addr,
        Err(e) => return HttpResponse::BadRequest().body(format!("Invalid Ethereum address: {}", e)),
    };
    
    if ethereum_address.len() != 20 {
        return HttpResponse::BadRequest().body("Ethereum address must be 20 bytes");
    }

    let mut eth_addr_array = [0u8; 20];
    eth_addr_array.copy_from_slice(&ethereum_address);

    match enclave.get_public_key(&eth_addr_array) {
        Ok(public_key) => HttpResponse::Ok().json(GetPublicKeyResponse {
            public_key: public_key.to_string(),
        }),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // TODO (powvt): read seed from cli params for all hardcoded values
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let enclave = Arc::new(SecureEnclave::new(&seed).unwrap());
    let enclave_data = web::Data::new(enclave);

    HttpServer::new(move || {
        App::new()
            .app_data(enclave_data.clone())
            .route("/derive_address", web::post().to(derive_address))
            .route("/sign_transaction", web::post().to(sign_transaction))
            .route("/get_public_key", web::post().to(get_public_key))
    })
    .bind("127.0.0.1:5555")?
    .run()
    .await
}