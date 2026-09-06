//! Axum HTTP routes for the zkAPI server.
//!
//! Endpoints:
//! - POST /v1/requests              -- submit an API request
//! - POST /v1/withdraw/clearance    -- request mutual-close clearance
//! - GET  /v1/requests/:id          -- recover by client_request_id
//! - GET  /v1/nullifiers/:nullifier -- recover by nullifier

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};

use zkapi_core::poseidon::felt_to_field;
use zkapi_types::wire::{
    ApiRequest, ClearanceRequest, ClearanceResponse, ErrorResponse, RecoveryResponse,
    RequestResponse,
};
use zkapi_types::Felt252;

use crate::error::ServerError;
use crate::processor::RequestProcessor;
use crate::provider::EchoProvider;

/// Shared application state.
type AppState = Arc<RequestProcessor>;

/// Start the HTTP server with the given config.
pub async fn run_server(config: crate::config::ServerConfig) -> anyhow::Result<()> {
    let store = Arc::new(crate::nullifier_store::NullifierStore::new(
        &config.db_path,
    )?);
    let signer = Arc::new(crate::signer::ServerSigner::with_height_durable(
        felt_to_field(&config.state_seed),
        felt_to_field(&config.clear_seed),
        config.epoch,
        config.xmss_height,
        &config.db_path,
    )?);
    let provider = Arc::new(EchoProvider::default());
    let processor = Arc::new(RequestProcessor::new(
        config.clone(),
        store,
        signer,
        provider,
        config.initial_root,
    ));
    let router = create_router(processor);
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!("Server listening on {}", config.listen_addr);
    axum::serve(listener, router).await?;
    Ok(())
}

/// Create the Axum router with all zkAPI server routes.
pub fn create_router(processor: Arc<RequestProcessor>) -> Router {
    Router::new()
        .route("/v1/requests", post(handle_request))
        .route("/v1/withdraw/clearance", post(handle_clearance))
        .route(
            "/v1/requests/{client_request_id}",
            get(handle_recovery_by_id),
        )
        .route(
            "/v1/nullifiers/{nullifier}",
            get(handle_recovery_by_nullifier),
        )
        .with_state(processor)
}

/// POST /v1/requests -- process an API request.
async fn handle_request(
    State(processor): State<AppState>,
    Json(api_request): Json<ApiRequest>,
) -> Result<Json<RequestResponse>, (StatusCode, Json<ErrorResponse>)> {
    processor
        .process_request(&api_request)
        .map(Json)
        .map_err(|e| error_to_response(&e, &api_request.client_request_id, &processor))
}

/// POST /v1/withdraw/clearance -- request a clearance signature.
async fn handle_clearance(
    State(processor): State<AppState>,
    Json(clearance_req): Json<ClearanceRequest>,
) -> Result<Json<ClearanceResponse>, (StatusCode, Json<ErrorResponse>)> {
    processor
        .process_clearance(&clearance_req)
        .map(Json)
        .map_err(|e| {
            error_to_response(&e, &clearance_req.withdrawal_nullifier.to_hex(), &processor)
        })
}

/// GET /v1/requests/:client_request_id -- recover a response by client request ID.
async fn handle_recovery_by_id(
    State(processor): State<AppState>,
    Path(client_request_id): Path<String>,
) -> Result<Json<RecoveryResponse>, (StatusCode, Json<ErrorResponse>)> {
    processor
        .recover_by_client_id(&client_request_id)
        .map(Json)
        .map_err(|e| error_to_response(&e, &client_request_id, &processor))
}

/// GET /v1/nullifiers/:nullifier -- recover a response by nullifier hex.
async fn handle_recovery_by_nullifier(
    State(processor): State<AppState>,
    Path(nullifier_hex): Path<String>,
) -> Result<Json<RecoveryResponse>, (StatusCode, Json<ErrorResponse>)> {
    let nullifier = Felt252::from_hex(&nullifier_hex).map_err(|e| {
        let err = ServerError::InvalidRequest(format!("invalid nullifier hex: {}", e));
        error_to_response(&err, &nullifier_hex, &processor)
    })?;

    processor
        .recover_by_nullifier(&nullifier)
        .map(Json)
        .map_err(|e| error_to_response(&e, &nullifier_hex, &processor))
}

/// Convert a ServerError into an HTTP error response tuple.
fn error_to_response(
    err: &ServerError,
    client_request_id: &str,
    processor: &RequestProcessor,
) -> (StatusCode, Json<ErrorResponse>) {
    let status_code = match err {
        ServerError::InvalidProof(_)
        | ServerError::InvalidRequest(_)
        | ServerError::ProtocolMismatch(_) => StatusCode::BAD_REQUEST,
        ServerError::StaleRoot { .. } => StatusCode::CONFLICT,
        ServerError::Replay | ServerError::NullifierUsed => StatusCode::CONFLICT,
        ServerError::NoteExpired => StatusCode::GONE,
        ServerError::CapacityExhausted => StatusCode::SERVICE_UNAVAILABLE,
        ServerError::Internal(_) | ServerError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };

    let latest_root = if matches!(err, ServerError::StaleRoot { .. }) {
        Some(processor.current_root())
    } else {
        None
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let body = ErrorResponse {
        status: "error".to_string(),
        client_request_id: client_request_id.to_string(),
        error_code: err.error_code().to_string(),
        error_message: err.to_string(),
        retriable: err.is_retriable(),
        latest_root,
        server_time_ms: Some(now_ms),
        retry_after_seconds: None,
    };

    (status_code, Json(body))
}
