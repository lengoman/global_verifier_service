use lambda_http::{run, service_fn, Body, Error, Request, Response};
use serde::Deserialize;
use serde_json;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use global_verifier_service::common::types::{VerifyRequest, VerifyResponse};
use global_verifier_service::common::verify::verify_signature;

// Store for used nonces to prevent replay attacks
type NonceStore = Arc<Mutex<HashSet<String>>>;

// Extension trait for Request to parse JSON body
trait RequestExt {
    fn parse_json<T: for<'de> Deserialize<'de>>(&self) -> Result<T, Error>;
}

impl RequestExt for Request {
    fn parse_json<T: for<'de> Deserialize<'de>>(&self) -> Result<T, Error> {
        match serde_json::from_slice(self.body().as_ref()) {
            Ok(value) => Ok(value),
            Err(e) => {
                tracing::error!("Failed to parse request: {:?}", e);
                Err(Error::from("Invalid request format"))
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .without_time()
        .init();

    // Create the nonce store
    let nonce_store: NonceStore = Arc::new(Mutex::new(HashSet::new()));

    run(service_fn(move |event: Request| {
        let nonce_store = nonce_store.clone();
        handler(event, nonce_store)
    })).await
}

async fn handler(event: Request, nonce_store: NonceStore) -> Result<Response<Body>, Error> {
    // Log the incoming request
    tracing::info!("Received request: {:?}", event.uri().path());
    tracing::info!("Request method: {:?}", event.method());

    // Route based on path
    match event.uri().path() {
        "/verify" => handle_verify_request(event, nonce_store).await,
        _ => Ok(Response::builder()
            .status(404)
            .body(Body::from("Not found"))?)
    }
}

async fn handle_verify_request(event: Request, nonce_store: NonceStore) -> Result<Response<Body>, Error> {
    tracing::info!("Processing verify request");

    // Parse the incoming request using the extension method
    let request: VerifyRequest = event.parse_json()?;

    // Check if nonce has been used before
    {
        let mut store = nonce_store.lock().await;
        if store.contains(&request.nonce) {
            tracing::warn!("Nonce already used: {}", request.nonce);
            return Ok(Response::builder()
                .status(400)
                .body(Body::from(serde_json::to_string(&VerifyResponse {
                    verified: false,
                    message: "Nonce already used".to_string(),
                })?))?)
        }
        store.insert(request.nonce.clone());
    }

    tracing::info!("Verifying signature for payload: {}", request.payload);

    // Decode the signature from base64
    let signature = match BASE64.decode(&request.signature) {
        Ok(sig) => sig,
        Err(e) => {
            tracing::error!("Failed to decode signature: {:?}", e);
            return Ok(Response::builder()
                .status(400)
                .body(Body::from(serde_json::to_string(&VerifyResponse {
                    verified: false,
                    message: "Invalid signature format".to_string(),
                })?))?)
        }
    };

    // Verify the signature using the shared module
    match verify_signature(&request.payload, &signature) {
        Ok(true) => {
            tracing::info!("Signature verified successfully");
            Ok(Response::builder()
                .status(200)
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&VerifyResponse {
                    verified: true,
                    message: "Signature verified successfully".to_string(),
                })?))?)
        },
        Ok(false) => {
            tracing::warn!("Invalid signature");
            Ok(Response::builder()
                .status(400)
                .body(Body::from(serde_json::to_string(&VerifyResponse {
                    verified: false,
                    message: "Invalid signature".to_string(),
                })?))?)
        },
        Err(e) => {
            tracing::error!("Error verifying signature: {:?}", e);
            Ok(Response::builder()
                .status(500)
                .body(Body::from(serde_json::to_string(&VerifyResponse {
                    verified: false,
                    message: "Error verifying signature".to_string(),
                })?))?)
        }
    }
}
