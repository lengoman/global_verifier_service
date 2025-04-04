use rsa::{RsaPublicKey, Pkcs1v15Sign};
use sha2::{Sha256, Digest};
use rsa::pkcs1::DecodeRsaPublicKey;
use std::env;

// The public key as a static string
const PUBLIC_KEY_PEM: &str = include_str!("../../public_key.pem");

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

/// Verifies a signature against a payload using the public key
pub fn verify_signature(payload: &str, signature: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
    // Load the public key
    let public_key = load_public_key()?;

    // Hash the payload
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    let hash = hasher.finalize();

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
