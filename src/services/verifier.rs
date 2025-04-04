use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;
use global_verifier_service::common::types::{VerifyRequest, VerifyResponse};
use global_verifier_service::common::verify;

// Store for used nonces to prevent replay attacks
type NonceStore = Arc<Mutex<HashSet<String>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Create the nonce store
    let nonce_store: NonceStore = Arc::new(Mutex::new(HashSet::new()));

    // Build our application with a route
    let app = Router::new()
        .route("/verify", post(verify_signature))
        .with_state(nonce_store);

    // Run it with hyper on localhost:3040
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3040").await?;
    tracing::info!("listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn verify_signature(
    State(nonce_store): State<NonceStore>,
    Json(payload): Json<VerifyRequest>,
) -> impl IntoResponse {
    // Check if nonce has been used before
    {
        let mut store = nonce_store.lock().await;
        if store.contains(&payload.nonce) {
            return (
                StatusCode::BAD_REQUEST,
                Json(VerifyResponse {
                    verified: false,
                    message: "Nonce already used".to_string(),
                }),
            );
        }
        store.insert(payload.nonce.clone());
    }

    // Decode the signature from base64
    let signature = match BASE64.decode(&payload.signature) {
        Ok(sig) => sig,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(VerifyResponse {
                    verified: false,
                    message: "Invalid signature format".to_string(),
                }),
            );
        }
    };

    // Verify the signature using the shared module
    match verify::verify_signature(&payload.payload, &signature) {
        Ok(true) => (
            StatusCode::OK,
            Json(VerifyResponse {
                verified: true,
                message: "Signature verified successfully".to_string(),
            }),
        ),
        Ok(false) => (
            StatusCode::BAD_REQUEST,
            Json(VerifyResponse {
                verified: false,
                message: "Invalid signature".to_string(),
            }),
        ),
        Err(e) => {
            tracing::error!("Error verifying signature: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(VerifyResponse {
                    verified: false,
                    message: "Error verifying signature".to_string(),
                }),
            )
        }
    }
}
