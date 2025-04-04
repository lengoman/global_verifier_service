use serde::{Deserialize, Serialize};

/// Request structure for verification endpoints
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub payload: String,
    pub signature: String,
    pub nonce: String,
}

/// Response structure for verification endpoints
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub verified: bool,
    pub message: String,
}

/// Structure for signed payloads
#[derive(Serialize, Deserialize)]
pub struct SignedPayload {
    pub payload: String,
    pub signature: String,
    pub nonce: String,
} 