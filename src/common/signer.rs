use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::{json, Value};
use std::fs;
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Sign};
use sha2::{Sha256, Digest};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use serde::{Deserialize, Serialize};
use std::env;

// The public key as a static string
const PUBLIC_KEY_PEM: &str = include_str!("../../public_key.pem");

#[derive(Serialize, Deserialize)]
pub struct SignedPayload {
    pub payload: String,
    pub signature: String,
    pub nonce: String,
}

/// Loads the private key from environment variable or file
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

/// Loads the public key from either an environment variable or the embedded file
pub fn load_public_key() -> Result<RsaPublicKey, Box<dyn std::error::Error>> {
    // Try to load from environment variable first
    let public_key_pem = match env::var("PUBLIC_KEY_PEM") {
        Ok(key) => key,
        Err(_) => PUBLIC_KEY_PEM.to_string(),
    };

    // Parse the public key
    let public_key = RsaPublicKey::from_pkcs1_pem(&public_key_pem)?;
    Ok(public_key)
}

/// Creates a hash of the payload using SHA-256
pub fn hash_payload(payload: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    hasher.finalize().to_vec()
}

/// Signs a message with the private key
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
    let hash = hash_payload(&payload_str);

    // Sign the payload
    let signature = private_key.sign(
        Pkcs1v15Sign {
            hash_len: Some(32), // SHA-256 hash length
            prefix: vec![0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20].into(),
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

/// Verifies a signature against a payload using the public key
pub fn verify_signature(payload: &str, signature: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
    // Load the public key
    let public_key = load_public_key()?;

    // Try to parse the payload as JSON, but don't fail if it's not JSON
    let _ = serde_json::from_str::<Value>(payload);

    // Hash the payload
    let hash = hash_payload(payload);

    // Verify the signature
    match public_key.verify(
        Pkcs1v15Sign {
            hash_len: Some(32), // SHA-256 hash length
            prefix: vec![0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20].into(),
        },
        &hash,
        signature,
    ) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}
