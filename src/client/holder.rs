use reqwest;
use serde_json::json;
use global_verifier_service::common::signer::{sign_message, SignedPayload};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get the verifier service URL from command line arguments or use default
    let verifier_url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://localhost:3000/verify".to_string());

    println!("Using verifier service at: {}", verifier_url);

    // Create a payload
    let message = "Hello, World!";
    println!("Created message: {}", message);

    // Sign the payload
    let SignedPayload { payload, signature, nonce } = sign_message(message)?;
    println!("Generated signature: {}", signature);
    println!("Generated payload: {}", payload);
    println!("Generated nonce: {}", nonce);

    // Create the request body
    let request_body = json!({
        "payload": payload,
        "signature": signature,
        "nonce": nonce
    });

    println!("Sending request to verifier service...");
    println!("Request body: {}", request_body);

    // Send the request to the verifier service
    let client = reqwest::Client::new();
    let response = client
        .post(&verifier_url)
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await?;

    // Check if the request was successful
    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await?;
        println!("Error: Server returned status {} with body: {}", status, text);
        return Err(format!("Server returned status {}", status).into());
    }

    // Get the response text first
    let response_text = response.text().await?;
    println!("Raw response: {}", response_text);

    // Try to parse the response as JSON
    match serde_json::from_str::<serde_json::Value>(&response_text) {
        Ok(response_body) => {
            println!("Parsed response: {:?}", response_body);
            Ok(())
        },
        Err(e) => {
            println!("Error parsing JSON response: {}", e);
            Err(format!("Failed to parse JSON response: {}", e).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use global_verifier_service::test_utils;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use uuid::Uuid;

    fn setup_test_environment() -> Result<(String, String), Box<dyn std::error::Error>> {
        Ok(test_utils::setup_test_environment())
    }

    #[test]
    fn test_sign_and_encode() -> Result<(), Box<dyn std::error::Error>> {
        let (payload, _) = setup_test_environment()?;

        // Sign the payload
        let SignedPayload { signature, .. } = sign_message(&payload)?;

        // Verify the signature is not empty
        assert!(!signature.is_empty());

        // Verify the signature can be decoded
        let decoded = BASE64.decode(&signature)?;
        assert!(!decoded.is_empty());
        Ok(())
    }

    #[test]
    fn test_nonce_generation() {
        let nonce1 = Uuid::new_v4().to_string();
        let nonce2 = Uuid::new_v4().to_string();

        // Verify nonces are not empty
        assert!(!nonce1.is_empty());
        assert!(!nonce2.is_empty());

        // Verify nonces are different
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_request_body_creation() -> Result<(), Box<dyn std::error::Error>> {
        let (payload, _) = setup_test_environment()?;

        // Sign the payload
        let SignedPayload { signature, payload, nonce } = sign_message(&payload)?;

        // Create request body
        let request_body = json!({
            "payload": payload,
            "signature": signature,
            "nonce": nonce
        });

        // Verify the request body has the required fields
        assert!(request_body["payload"].as_str().is_some());
        assert!(request_body["signature"].as_str().is_some());
        assert!(request_body["nonce"].as_str().is_some());
        Ok(())
    }
}
