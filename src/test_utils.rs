use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use crate::common::signer::{sign_message, SignedPayload};
use serde_json::json;

/// Creates a test environment with a temporary private key file
pub fn setup_test_environment() -> (String, String) {
    // Create a test verifier URL
    let verifier_url = "http://localhost:3000".to_string();
    
    // Create a test payload
    let payload = json!({
        "message": "Hello, World!",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "nonce": format!("nonce-{}", chrono::Utc::now().timestamp())
    }).to_string();
    
    (payload, verifier_url)
}

/// Creates a signed payload for testing
pub fn create_signed_payload(message: &str) -> (String, String, String) {
    // Sign the message
    let SignedPayload { payload, signature, nonce } = sign_message(message).unwrap();
    let signature_b64 = signature;
    
    (payload, signature_b64, nonce)
}

/// Verifies that a signature is valid for a payload
pub fn verify_signature_valid(payload: &str, signature_b64: &str) -> bool {
    let signature = BASE64.decode(signature_b64).unwrap();
    crate::common::verify::verify_signature(payload, &signature).unwrap()
} 