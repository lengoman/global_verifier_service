use axum::{
    routing::post,
    Router,
    Json,
    extract::State,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashSet;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use global_verifier_service::common::verify;
use std::net::SocketAddr;

// Define the request and response types
#[derive(Deserialize, Serialize)]
struct VerifyRequest {
    payload: String,
    signature: String,
    nonce: String,
}

#[derive(Deserialize, Serialize)]
struct VerifyResponse {
    verified: bool,
    message: String,
}

// Define the nonce store type
type NonceStore = Arc<Mutex<HashSet<String>>>;

// Create a new router with the verify endpoint
pub fn create_router() -> Router {
    let nonce_store: NonceStore = Arc::new(Mutex::new(HashSet::new()));

    Router::new()
        .route("/verify", post(handle_verify_request))
        .with_state(nonce_store)
}

// Handle the verify request
async fn handle_verify_request(
    State(nonce_store): State<NonceStore>,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, StatusCode> {
    println!("Received verify request with payload: {}", request.payload);

    // Check if the nonce has been used before
    {
        let mut nonces = nonce_store.lock().await;
        if nonces.contains(&request.nonce) {
            return Ok(Json(VerifyResponse {
                verified: false,
                message: "Nonce already used".to_string(),
            }));
        }
        nonces.insert(request.nonce.clone());
    }

    // Decode the signature from base64
    let signature = match BASE64.decode(request.signature) {
        Ok(sig) => sig,
        Err(_) => {
            return Ok(Json(VerifyResponse {
                verified: false,
                message: "Invalid signature format".to_string(),
            }));
        }
    };

    // Verify the signature
    match verify::verify_signature(&request.payload, &signature) {
        Ok(true) => Ok(Json(VerifyResponse {
            verified: true,
            message: "Signature verified successfully".to_string(),
        })),
        Ok(false) => Ok(Json(VerifyResponse {
            verified: false,
            message: "Invalid signature".to_string(),
        })),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        Router,
    };
    use axum::body::to_bytes;
    use tower::ServiceExt;
    use global_verifier_service::test_utils;

    async fn setup_test_router() -> Router {
        create_router()
    }

    #[tokio::test]
    async fn test_verify_valid_signature() -> Result<(), Box<dyn std::error::Error>> {
        let app = setup_test_router().await;

        // Create a signed payload
        let (payload, signature_b64, nonce) = test_utils::create_signed_payload("Hello, World!")?;

        // Create request
        let request = VerifyRequest {
            payload,
            signature: signature_b64,
            nonce,
        };

        // Send request
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/verify")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&request)?))
                    .map_err(|e| format!("Failed to build request: {}", e))?,
            )
            .await
            .map_err(|e| format!("Failed to send request: {}", e))?;

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let response: VerifyResponse = serde_json::from_slice(&body)?;

        assert!(response.verified);
        assert_eq!(response.message, "Signature verified successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_invalid_signature() -> Result<(), Box<dyn std::error::Error>> {
        let app = setup_test_router().await;

        // Create request with invalid signature
        let request = VerifyRequest {
            payload: "Hello, World!".to_string(),
            signature: BASE64.encode(vec![0u8; 256]), // Invalid signature
            nonce: "test-nonce-2".to_string(),
        };

        // Send request
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/verify")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&request)?))
                    .map_err(|e| format!("Failed to build request: {}", e))?,
            )
            .await
            .map_err(|e| format!("Failed to send request: {}", e))?;

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let response: VerifyResponse = serde_json::from_slice(&body)?;

        assert!(!response.verified);
        assert_eq!(response.message, "Invalid signature");
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_duplicate_nonce() -> Result<(), Box<dyn std::error::Error>> {
        let app = setup_test_router().await;

        // Create a signed payload
        let (payload, signature_b64, nonce) = test_utils::create_signed_payload("Hello, World!")?;

        // Create request
        let request = VerifyRequest {
            payload,
            signature: signature_b64,
            nonce: nonce.clone(),
        };

        // Send request twice
        let response1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/verify")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&request)?))
                    .map_err(|e| format!("Failed to build request: {}", e))?,
            )
            .await
            .map_err(|e| format!("Failed to send request: {}", e))?;

        let response2 = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/verify")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&request)?))
                    .map_err(|e| format!("Failed to build request: {}", e))?,
            )
            .await
            .map_err(|e| format!("Failed to send request: {}", e))?;

        assert_eq!(response1.status(), StatusCode::OK);
        assert_eq!(response2.status(), StatusCode::OK);

        let body1 = to_bytes(response1.into_body(), usize::MAX).await?;
        let body2 = to_bytes(response2.into_body(), usize::MAX).await?;

        let response1: VerifyResponse = serde_json::from_slice(&body1)?;
        let response2: VerifyResponse = serde_json::from_slice(&body2)?;

        assert!(response1.verified);
        assert!(!response2.verified);
        assert_eq!(response2.message, "Nonce already used");
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create the router
    let app = create_router();

    // Define the address to listen on
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Verifier service listening on {}", addr);

    // Run the server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
