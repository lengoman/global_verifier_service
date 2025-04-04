use crate::common::signer::verify_signature as verify_signature_impl;
use serde_json::Value;

/// Re-exports the verify_signature function from signer.rs
pub fn verify_signature(payload: &str, signature: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
    // Try to parse the payload as JSON, but don't fail if it's not JSON
    let _ = serde_json::from_str::<Value>(payload);
    
    // Use the implementation from signer.rs
    verify_signature_impl(payload, signature)
}
