use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::json;
use std::fs;
use rsa::{RsaPrivateKey, Pkcs1v15Sign};
use sha2::{Sha256, Digest};
use rsa::pkcs1::DecodeRsaPrivateKey;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Serialize, Deserialize)]
pub struct SignedPayload {
    pub payload: String,
    pub signature: String,
    pub nonce: String,
}

pub fn load_private_key() -> Result<RsaPrivateKey, Box<dyn std::error::Error>> {
    // Load the private key from environment variable or file
    let private_key_pem = match env::var("PRIVATE_KEY_PEM") {
        Ok(key) => key,
        Err(_) => fs::read_to_string("private_key.pem")?,
    };

    // Parse the private key
    let private_key = RsaPrivateKey::from_pkcs1_pem(&private_key_pem)?;
    Ok(private_key)
}

pub fn sign_message(message: &str) -> Result<SignedPayload, Box<dyn std::error::Error>> {
    let private_key = load_private_key()?;

    // Create a payload with a nonce
    let nonce = format!("nonce-{}", chrono::Utc::now().timestamp());
    let payload = json!({
        "message": message,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "nonce": nonce
    });
    let payload_str = payload.to_string();

    // Hash the payload
    let mut hasher = Sha256::new();
    hasher.update(payload_str.as_bytes());
    let hash = hasher.finalize();

    // Sign the payload
    let signature = private_key.sign(
        Pkcs1v15Sign {
            hash_len: Some(32), // SHA-256 hash length
            prefix: vec![0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20].into(), // Just a random prefix
        },
        &hash,
    )?;
    let signature_b64 = BASE64.encode(&signature);

    Ok(SignedPayload {
        payload: payload_str,
        signature: signature_b64,
        nonce,
    })
}
