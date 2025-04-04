use reqwest::Client;
use serde_json::json;
use std::env;

use global_verifier_service::common::signer::sign_message;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get the service URL from command line arguments or use default
    let args: Vec<String> = env::args().collect();
    let service_url = if args.len() > 1 {
        args[1].clone()
    } else {
        "http://localhost:3040/verify".to_string()
    };

    println!("Using verifier service at: {}", service_url);

    // Sign the message
    let signed_payload = sign_message("Hello, World!")?;

    // Send to verifier
    let client = Client::new();
    let response = client
        .post(&service_url)
        .json(&json!({
            "payload": signed_payload.payload,
            "signature": signed_payload.signature,
            "nonce": signed_payload.nonce
        }))
        .send()
        .await?;

    println!("Response: {:?}", response.text().await?);
    Ok(())
}
