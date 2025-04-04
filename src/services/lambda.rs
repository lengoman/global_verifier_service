use std::collections::HashSet;
use std::sync::Arc;
use lambda_http::{run, service_fn, Body, Error, Request, Response};
use serde_json::json;
use tokio::sync::Mutex;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use global_verifier_service::common::verify;

// Define the nonce store type
type NonceStore = Arc<Mutex<HashSet<String>>>;

/// Main function for the Lambda handler
#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .without_time()
        .with_line_number(false)
        .init();

    let nonce_store: NonceStore = Arc::new(Mutex::new(HashSet::new()));
    run(service_fn(|event| handle_request(event, nonce_store.clone()))).await
}

/// Handle the incoming request
async fn handle_request(event: Request, nonce_store: NonceStore) -> Result<Response<Body>, Error> {
    println!("Received request: {:?}", event);

    // Get the path from the request
    let path = event.uri().path();
    println!("Request path: {}", path);

    // Handle both root path and /verify path
    if path == "/" || path == "/verify" {
        handle_verify_request(event, nonce_store).await
    } else {
        Ok(Response::builder()
            .status(404)
            .body(Body::from("Not Found"))
            .map_err(|e| Error::from(format!("Failed to build response: {}", e)))?)
    }
}

/// Handle the verify request
async fn handle_verify_request(event: Request, nonce_store: NonceStore) -> Result<Response<Body>, Error> {
    println!("Processing verify request");

    // Parse the request body
    let body = event.body();
    let request: serde_json::Value = serde_json::from_slice(body)?;
    println!("Request body: {:?}", request);

    // Extract the required fields
    let payload = request["payload"].as_str().ok_or_else(|| Error::from("Missing payload"))?;
    let signature = request["signature"].as_str().ok_or_else(|| Error::from("Missing signature"))?;
    let nonce = request["nonce"].as_str().ok_or_else(|| Error::from("Missing nonce"))?;

    println!("Received payload: {}", payload);
    println!("Received signature: {}", signature);
    println!("Received nonce: {}", nonce);

    // Check if the nonce has been used before
    {
        let mut nonces = nonce_store.lock().await;
        if nonces.contains(nonce) {
            return Ok(Response::builder()
                .status(200)
                .body(Body::from(json!({
                    "verified": false,
                    "message": "Nonce already used"
                }).to_string()))
                .map_err(|e| Error::from(format!("Failed to build response: {}", e)))?);
        }
        nonces.insert(nonce.to_string());
    }

    // Decode the signature from base64
    let signature_bytes = match BASE64.decode(signature) {
        Ok(sig) => sig,
        Err(_) => {
            return Ok(Response::builder()
                .status(200)
                .body(Body::from(json!({
                    "verified": false,
                    "message": "Invalid signature format"
                }).to_string()))
                .map_err(|e| Error::from(format!("Failed to build response: {}", e)))?);
        }
    };

    // Verify the signature
    match verify::verify_signature(payload, &signature_bytes) {
        Ok(true) => Ok(Response::builder()
            .status(200)
            .body(Body::from(json!({
                "verified": true,
                "message": "Signature verified successfully"
            }).to_string()))
            .map_err(|e| Error::from(format!("Failed to build response: {}", e)))?),
        Ok(false) => Ok(Response::builder()
            .status(200)
            .body(Body::from(json!({
                "verified": false,
                "message": "Invalid signature"
            }).to_string()))
            .map_err(|e| Error::from(format!("Failed to build response: {}", e)))?),
        Err(_) => Ok(Response::builder()
            .status(500)
            .body(Body::from(json!({
                "verified": false,
                "message": "Internal server error"
            }).to_string()))
            .map_err(|e| Error::from(format!("Failed to build response: {}", e)))?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lambda_http::http::Request;
    use wiremock::http::Method;
    use global_verifier_service::test_utils;

    async fn setup_test_request(payload: &str, signature: &str, nonce: &str) -> Result<Request<Body>, Error> {
        let body = json!({
            "payload": payload,
            "signature": signature,
            "nonce": nonce
        }).to_string();

        Ok(Request::builder()
            .method(Method::Post)
            .uri("/verify")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .map_err(|e| Error::from(format!("Failed to build request: {}", e)))?)
    }

    #[tokio::test]
    async fn test_handle_verify_request_valid() -> Result<(), Box<dyn std::error::Error>> {
        // Create a nonce store
        let nonce_store: NonceStore = Arc::new(Mutex::new(HashSet::new()));

        // Create a payload and sign it
        let (payload, signature_b64, nonce) = test_utils::create_signed_payload("Hello, World!")?;

        // Create request
        let request = setup_test_request(&payload, &signature_b64, &nonce).await?;

        // Handle request
        let response = handle_verify_request(request, nonce_store).await?;

        // Check response
        assert_eq!(response.status(), 200);

        let body = response.into_body();
        let body_bytes = match body {
            Body::Text(text) => text.into_bytes(),
            Body::Binary(bytes) => bytes,
            _ => return Err("Unexpected body type".into()),
        };
        let response: serde_json::Value = serde_json::from_slice(&body_bytes)?;

        assert!(response["verified"].as_bool().ok_or("Missing verified field")?);
        assert_eq!(response["message"].as_str().ok_or("Missing message field")?, "Signature verified successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_handle_verify_request_invalid_signature() -> Result<(), Box<dyn std::error::Error>> {
        // Create a nonce store
        let nonce_store: NonceStore = Arc::new(Mutex::new(HashSet::new()));

        // Create request with invalid signature
        let request = setup_test_request(
            "Hello, World!",
            &BASE64.encode(vec![0u8; 256]),
            "test-nonce-2"
        ).await?;

        // Handle request
        let response = handle_verify_request(request, nonce_store).await?;

        // Check response
        assert_eq!(response.status(), 200);

        let body = response.into_body();
        let body_bytes = match body {
            Body::Text(text) => text.into_bytes(),
            Body::Binary(bytes) => bytes,
            _ => return Err("Unexpected body type".into()),
        };
        let response: serde_json::Value = serde_json::from_slice(&body_bytes)?;

        assert!(!response["verified"].as_bool().ok_or("Missing verified field")?);
        assert_eq!(response["message"].as_str().ok_or("Missing message field")?, "Invalid signature");
        Ok(())
    }

    #[tokio::test]
    async fn test_handle_verify_request_invalid_base64() -> Result<(), Box<dyn std::error::Error>> {
        // Create a nonce store
        let nonce_store: NonceStore = Arc::new(Mutex::new(HashSet::new()));

        // Create request with invalid base64
        let request = setup_test_request(
            "Hello, World!",
            "invalid-base64",
            "test-nonce-3"
        ).await?;

        // Handle request
        let response = handle_verify_request(request, nonce_store).await?;

        // Check response
        assert_eq!(response.status(), 200);

        let body = response.into_body();
        let body_bytes = match body {
            Body::Text(text) => text.into_bytes(),
            Body::Binary(bytes) => bytes,
            _ => return Err("Unexpected body type".into()),
        };
        let response: serde_json::Value = serde_json::from_slice(&body_bytes)?;

        assert!(!response["verified"].as_bool().ok_or("Missing verified field")?);
        assert_eq!(response["message"].as_str().ok_or("Missing message field")?, "Invalid signature format");
        Ok(())
    }

    #[tokio::test]
    async fn test_handle_request_invalid_path() -> Result<(), Box<dyn std::error::Error>> {
        // Create a nonce store
        let nonce_store: NonceStore = Arc::new(Mutex::new(HashSet::new()));

        // Create request with invalid path
        let request = Request::builder()
            .method(Method::Post)
            .uri("/invalid")
            .body(Body::from(""))
            .map_err(|e| Error::from(format!("Failed to build request: {}", e)))?;

        // Handle request
        let response = handle_request(request, nonce_store).await?;

        // Check response
        assert_eq!(response.status(), 404);
        Ok(())
    }
}
