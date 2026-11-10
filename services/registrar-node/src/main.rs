// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

mod config;
mod runtime_config;
use config::*;

use anyhow::{anyhow, Result};
use axum::{
    extract::{Path as AxumPath, Query, State},
    http::{header, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Datelike, Duration, Utc};
use futures::TryStreamExt;
use oan_core::{CapabilityTagTree, CryptoSuite, DidDocument, ResourceType};
use oan_credentials::{
    sign_credential, validate_resource_registration_credential, CredentialStatusReference,
    ExternalIdentifierReference, OanIdentity, OanResourceRegistrationCredential,
    ResourceRegistrationCredentialSubject,
};
use oan_crypto::{
    hash_json_with_suite, signing_key_from_private_key_jwk,
    verify_did_document_proof_compatible_value_isolated, verify_payload_with_proof,
    verifying_key_from_method, SigningKey, VerifiedWireDidDocument,
};
use oan_protocol::{
    validate_resource_routing_code, HealthResponse, RegistrationCredentialQueryRequest,
    ResourceRegistrationSubmission, ResourceVerifyAndPublishRequest, OAN_RESOURCE_PROTOCOL_VERSION,
    PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH, PROTOCOL_REGISTRATION_CREDENTIAL_QUERY_V1,
    PURPOSE_CONTROLLER_AUTHORIZATION_REGISTRATION, PURPOSE_REGISTRATION_CREDENTIAL_QUERY,
    PURPOSE_VERIFY_AND_PUBLISH,
};
use oan_semantic_recommender::{
    normalize_capability_tags, RegistrationSuggestionContext, RegistrationSuggestionInput,
    SemanticRecommender,
};
use oan_service_security::{
    create_signed_request_envelope, find_relationship_method, request_id, request_nonce,
    verify_and_store_nonce, verify_controller_authorization_proof_with_document,
    ControllerAuthorizationVerificationContext, SignedRequestEnvelopeInput,
    VerificationRelationship,
};
use oan_storage::{
    did_to_file_name, DatabaseBackend, DatabaseConfig, JsonStore, NamespacePageCursor,
    PostgresJsonStore, QueryLimits, SqliteJsonStore,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::{net::SocketAddr, sync::Arc, time::Instant};
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};

#[derive(Clone)]
struct AppState {
    data: JsonStore,
    config: Config,
    did: String,
    signing_key: SigningKey,
    sqlite: Option<SqliteJsonStore>,
    postgres: Option<PostgresJsonStore>,
    client: reqwest::Client,
    recommender: Arc<SemanticRecommender>,
    stats_cache: Arc<tokio::sync::Mutex<Option<(Instant, Value)>>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct ResourceListQuery {
    #[serde(rename = "afterDid")]
    after_did: Option<String>,
    limit: Option<u32>,
}

const REGISTRAR_DEFAULT_PAGE_SIZE: u32 = 100;
const REGISTRAR_MAX_PAGE_SIZE: u32 = 500;
const REGISTRAR_MAX_RECORD_BYTES: usize = 1024 * 1024;
const REGISTRAR_MAX_PAGE_BYTES: usize = 8 * 1024 * 1024;
const CONTROLLER_INDEX_BACKFILL_PAGE_SIZE: u32 = 100;
const CONTROLLER_INDEX_BACKFILL_MAX_RECORDS: usize = 500;
const CONTROLLER_INDEX_BACKFILL_STATE_FILE: &str = "controller-index/backfill-state.json";

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ControllerBackfillState {
    updated_at: String,
    record_key: String,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn internal(error: impl Into<anyhow::Error>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.into().to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

type ApiResult<T> = std::result::Result<Json<T>, ApiError>;

const REGISTRATION_CREDENTIAL_QUERY_MAX_CLOCK_SKEW_SECONDS: i64 = 300;
const REGISTRATION_CREDENTIAL_QUERY_NONCE_TTL_SECONDS: i64 = 600;

fn main() -> Result<()> {
    let cli = oan_config::NodeCli::parse();
    if matches!(
        cli.command,
        Some(
            oan_config::NodeCommand::SemanticRebuild(_)
                | oan_config::NodeCommand::SemanticBackfillSkipped(_)
                | oan_config::NodeCommand::SemanticEvaluate(_)
                | oan_config::NodeCommand::SemanticRebuildEvaluate(_)
        )
    ) {
        return Err(anyhow!(
            "semantic commands are supported only by discovery-node"
        ));
    }
    if cli.legacy_config.is_some() {
        eprintln!("deprecated positional configuration path; use --config");
    }
    let path = cli.path("services/registrar-node/config.example.toml")?;
    let (config, sources) = load_config_details(path.to_string_lossy().into_owned())?;
    if cli.inspect(&config, &sources)? {
        return Ok(());
    }
    let runtime = config.runtime.build()?;
    oan_crypto::initialize_did_verification_executor(config.runtime.did_verification)
        .map_err(|e| anyhow!(e))?;
    runtime.block_on(async { tokio::spawn(async_main(config)).await? })
}

async fn async_main(config: Config) -> Result<()> {
    validate_stats_report_config(&config.stats_report)?;
    let identity: OanIdentity = JsonStore::new(".").read(&config.paths.identity_file)?;
    identity
        .validate_data_integrity()
        .await
        .map_err(|err| anyhow!("invalid OAN Identity: {err}"))?;
    let did_doc: DidDocument = identity.did_document.clone();
    did_doc
        .validate_infrastructure_profile(ResourceType::RegistrarNode)
        .map_err(|error| anyhow!("invalid registrar DID document profile: {error}"))?;
    let signing_key =
        signing_key_from_private_key_jwk(CryptoSuite::Ed25519Sha256, &identity.private_key_jwk)?;
    // Public projection used by existing registration paths; identity.json remains authoritative.
    JsonStore::new(&config.paths.data_dir).write("did-document.json", &did_doc)?;
    let (sqlite, postgres) = match config.paths.database_url.as_deref() {
        Some(url) if !url.is_empty() => {
            let database = DatabaseConfig::parse(url)?;
            match database.backend() {
                DatabaseBackend::Sqlite => {
                    let sqlite = SqliteJsonStore::connect_with_pool(
                        url,
                        &runtime_config::pool_options(&config.database.pool, url)?,
                    )
                    .await?;
                    (Some(sqlite), None)
                }
                DatabaseBackend::Postgres => {
                    let postgres = PostgresJsonStore::connect_with_pool(
                        url,
                        &runtime_config::pool_options(&config.database.pool, url)?,
                    )
                    .await?;
                    (None, Some(postgres))
                }
            }
        }
        _ => (None, None),
    };
    let state = AppState {
        data: JsonStore::new(&config.paths.data_dir),
        config: config.clone(),
        did: identity.did,
        signing_key,
        sqlite,
        postgres,
        client: reqwest::Client::new(),
        recommender: Arc::new(SemanticRecommender::new()?),
        stats_cache: Arc::new(tokio::sync::Mutex::new(None)),
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/registrar/did", get(registrar_did_document))
        .route("/resources/register", post(register_resource_raw))
        .route("/resources/submit", post(register_resource_raw))
        .route("/registrar/status", get(api_status))
        .route("/registrar/stats", get(api_stats))
        .route("/registrar/root-authorization", get(api_root_authorization))
        .route("/resources", get(api_resources))
        .route("/resources/{did}", get(api_resource_detail))
        .route(
            "/resources/{did}/status",
            get(api_registration_credential_status),
        )
        .route(
            "/resources/{did}/registration-credential",
            post(api_registration_credential),
        )
        .route("/capability-tree", get(api_capability_tree))
        .route("/capability-tags/suggest", post(api_suggest_tags))
        .route("/capability-tags/normalize", post(api_normalize_tags))
        .route(
            "/registration/domain-catalog",
            get(api_registration_domain_catalog),
        )
        .route(
            "/registration/suggestions",
            post(api_registration_suggestions),
        )
        .layer(build_cors_layer(&config.cors)?)
        .with_state(state.clone());

    let backfill_state = state.clone();
    tokio::spawn(async move {
        if let Err(error) = backfill_controller_index(&backfill_state).await {
            eprintln!("controller index backfill failed: {error}");
        }
    });

    if state.config.stats_report.enabled {
        let report_state = state.clone();
        tokio::spawn(async move {
            registrar_stats_report_loop(report_state).await;
        });
    }

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port).parse()?;
    println!("registrar-node listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn validate_stats_report_config(config: &StatsReportConfig) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }
    if config
        .node_id
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err(anyhow!("stats_report.node_id is required when enabled"));
    }
    if config
        .endpoint
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err(anyhow!("stats_report.endpoint is required when enabled"));
    }
    if config
        .token
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err(anyhow!("stats_report.token is required when enabled"));
    }
    if config.interval_seconds == 0 {
        return Err(anyhow!(
            "stats_report.interval_seconds must be greater than 0"
        ));
    }
    Ok(())
}

fn build_cors_layer(config: &CorsConfig) -> Result<CorsLayer> {
    let origins: Vec<HeaderValue> = config
        .allowed_origins
        .iter()
        .map(|origin| HeaderValue::from_str(origin))
        .collect::<std::result::Result<_, _>>()?;
    Ok(CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::OPTIONS])
        .allow_headers(AllowHeaders::any()))
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_owned(),
        node_type: "registrar".to_owned(),
        did: Some(state.did),
    })
}

async fn registrar_did_document(State(state): State<AppState>) -> ApiResult<DidDocument> {
    state
        .data
        .read("did-document.json")
        .map(Json)
        .map_err(ApiError::internal)
}

async fn register_resource_raw(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> ApiResult<Value> {
    let did_document = payload
        .get("didDocument")
        .cloned()
        .ok_or_else(|| ApiError::bad_request("did_document_missing"))?;
    let verified_did_document = verify_registration_did_document_for_wire(did_document).await?;
    let submission: ResourceRegistrationSubmission = serde_json::from_value(payload)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    register_resource_with_raw_document(state, submission, verified_did_document).await
}


async fn register_resource_with_raw_document(
    state: AppState,
    submission: ResourceRegistrationSubmission,
    verified_did_document: VerifiedWireDidDocument,
) -> ApiResult<Value> {
    validate_resource_routing_code(&submission.resource_did, &state.did)
        .map_err(ApiError::bad_request)?;
    submission.validate_shape().map_err(ApiError::bad_request)?;
    verify_controller_authorization_for_submission(&state, &submission)
        .await
        .map_err(ApiError::bad_request)?;
    let authorized_domains =
        validate_resource_authorized_domains_for_registrar(&state, &submission)?;
    let request = build_resource_verify_and_publish_request_with_raw(
        &state,
        submission.clone(),
        verified_did_document.as_value().clone(),
    )?;
    let response = state
        .client
        .post(format!(
            "{}{}",
            state.config.upstream.root_endpoint, PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH
        ))
        .json(&request)
        .send()
        .await
        .map_err(ApiError::internal)?;
    let status = response.status();
    let body: Value = response.json().await.unwrap_or_else(|_| json!({}));
    if !status.is_success() {
        return Err(ApiError {
            status,
            message: body
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("root_resource_registration_failed")
                .to_owned(),
        });
    }
    validate_root_acceptance_response(&body, &submission)?;
    let did_document_hash =
        hash_json_with_suite(state.signing_key.crypto_suite(), &submission.did_document)
            .map_err(ApiError::internal)?;
    let registration_credential =
        issue_resource_registration_credential(&state, &submission, &did_document_hash)?;
    let mut record = json!({
        "resourceDid": submission.resource_did,
        "resourceType": submission.resource_type,
        "packageVersion": submission.package_version,
        "didDocumentHash": did_document_hash,
        "metadataHash": submission.metadata_hash,
        "packageHash": submission.package_hash,
        "didDocument": submission.did_document,
        "authorizedDomains": authorized_domains,
        "registrationCredential": registration_credential,
        "rootResponse": body,
        "submittedAt": chrono::Utc::now()
    });
    if let Some(access) = build_registration_credential_access(&state, &submission).await {
        record["registrationCredentialAccess"] = access;
    }
    write_resource_record(&state, &record).await?;
    if submission
        .did_document
        .oan_metadata
        .as_ref()
        .and_then(|metadata| metadata.controller_did.as_deref())
        == Some(submission.resource_did.as_str())
    {
        if let Err(error) =
            upsert_controller_index_from_document(&state, &submission.did_document).await
        {
            eprintln!(
                "resource {} accepted but controller index update is pending: {error}",
                submission.resource_did
            );
        }
    }
    Ok(Json(json!({
        "status": "submitted",
        "resourceDid": record["resourceDid"],
        "resourceType": record["resourceType"],
        "registrationCredential": record["registrationCredential"],
        "rootResponse": record["rootResponse"]
    })))
}

async fn verify_registration_did_document_for_wire(
    raw_did_document: Value,
) -> std::result::Result<VerifiedWireDidDocument, ApiError> {
    verify_did_document_proof_compatible_value_isolated(raw_did_document)
        .await
        .map_err(|error| ApiError::bad_request(error.to_string()))
}

async fn verify_controller_authorization_for_submission(
    state: &AppState,
    submission: &ResourceRegistrationSubmission,
) -> std::result::Result<(), String> {
    let next_controller_did = submission
        .did_document
        .registration_controller()
        .map_err(|error| error.to_string())?
        .0;
    let current_record = match read_resource_record(state, &submission.resource_did).await {
        Ok(record) => record,
        Err(error) => {
            eprintln!(
                "local resource state unavailable for {}; Root will decide: {error}",
                submission.resource_did
            );
            return Ok(());
        }
    };
    let (authorizer_did, trusted_document, authoritative_local_state) = if let Some(record) =
        current_record
    {
        let current_document: DidDocument = match record
            .get("didDocument")
            .cloned()
            .ok_or_else(|| "resource_record_did_document_missing".to_owned())
            .and_then(|value| {
                serde_json::from_value(value)
                    .map_err(|_| "resource_record_did_document_invalid".to_owned())
            }) {
            Ok(document) => document,
            Err(error) => {
                eprintln!(
                    "local resource state is unusable for {}; Root will decide: {error}",
                    submission.resource_did
                );
                return Ok(());
            }
        };
        let current_controller_did = match current_document
            .registration_controller()
            .map_err(|error| error.to_string())
        {
            Ok((controller_did, _)) => controller_did,
            Err(error) => {
                eprintln!(
                    "local controller state is unusable for {}; Root will decide: {error}",
                    submission.resource_did
                );
                return Ok(());
            }
        };
        if current_controller_did == submission.resource_did {
            return Ok(());
        }
        let document = match read_registered_resource_document(state, &current_controller_did).await
        {
            Ok(Some(document)) => document,
            Ok(None) => return Ok(()),
            Err(error) => {
                eprintln!(
                    "local authorizer state is unusable for {}; Root will decide: {error}",
                    submission.resource_did
                );
                return Ok(());
            }
        };
        (current_controller_did, document, false)
    } else {
        if next_controller_did == submission.resource_did {
            return Ok(());
        }
        let bundle = submission
            .controller_authorization_proof
            .as_ref()
            .ok_or_else(|| "controller_authorization_proof_required".to_owned())?;
        let document = match read_registered_resource_document(state, &next_controller_did).await? {
            Some(document) => document,
            None => {
                validate_controller_index(
                    state,
                    &bundle.controller_did_document,
                    &bundle.challenge.verification_method,
                )
                .await?;
                bundle.controller_did_document.clone()
            }
        };
        (next_controller_did, document, true)
    };
    let Some(bundle) = submission.controller_authorization_proof.as_ref() else {
        return if authoritative_local_state {
            Err("controller_authorization_proof_required".to_owned())
        } else {
            Ok(())
        };
    };
    let result = verify_controller_authorization_proof_with_document(
        bundle,
        &trusted_document,
        &ControllerAuthorizationVerificationContext {
            expected_resource_did: &submission.resource_did,
            expected_controller_did: &authorizer_did,
            expected_publisher_did: submission
                .did_document
                .oan_metadata
                .as_ref()
                .and_then(|metadata| metadata.publisher_did.as_deref()),
            expected_did_document_hash: &submission.did_document_hash,
            expected_metadata_hash: &submission.metadata_hash,
            expected_registrar_did: &state.did,
            expected_purpose: PURPOSE_CONTROLLER_AUTHORIZATION_REGISTRATION,
            max_clock_skew_seconds: 60,
            now: Utc::now(),
        },
    );
    match result {
        Ok(_) => Ok(()),
        Err(error) if !authoritative_local_state => {
            eprintln!(
                "local controller precheck deferred to Root for resource {}: {}",
                submission.resource_did, error
            );
            Ok(())
        }
        Err(error) => Err(error.to_string()),
    }
}

fn validate_root_acceptance_response(
    body: &Value,
    submission: &ResourceRegistrationSubmission,
) -> std::result::Result<(), ApiError> {
    let matches = body.get("status").and_then(Value::as_str)
        == Some("resource-verified-and-queued")
        && body.get("resourceDid").and_then(Value::as_str)
            == Some(submission.resource_did.as_str())
        && body.get("packageVersion").and_then(Value::as_str)
            == Some(submission.package_version.as_str())
        && body.get("didDocumentHash").and_then(Value::as_str)
            == Some(submission.did_document_hash.as_str())
        && body.get("metadataHash").and_then(Value::as_str)
            == Some(submission.metadata_hash.as_str())
        && body.get("packageHash").and_then(Value::as_str)
            == Some(submission.package_hash.as_str());
    if matches {
        Ok(())
    } else {
        Err(ApiError {
            status: StatusCode::BAD_GATEWAY,
            message: "root_resource_acceptance_mismatch".to_owned(),
        })
    }
}

async fn read_registered_resource_document(
    state: &AppState,
    resource_did: &str,
) -> std::result::Result<Option<DidDocument>, String> {
    let Some(record) = read_resource_record(state, resource_did)
        .await
        .map_err(|_| "resource_record_not_ready".to_owned())?
    else {
        return Ok(None);
    };
    let document: DidDocument = record
        .get("didDocument")
        .cloned()
        .ok_or_else(|| "resource_record_did_document_missing".to_owned())
        .and_then(|value| {
            serde_json::from_value(value)
                .map_err(|_| "resource_record_did_document_invalid".to_owned())
        })?;
    if document.id != resource_did {
        return Err("resource_record_did_document_mismatch".to_owned());
    }
    if document
        .oan_metadata
        .as_ref()
        .and_then(|metadata| metadata.lifecycle_state.as_deref())
        .is_some_and(|status| status != "active")
    {
        return Err("controller_inactive".to_owned());
    }
    Ok(Some(document))
}

async fn build_registration_credential_access(
    state: &AppState,
    submission: &ResourceRegistrationSubmission,
) -> Option<Value> {
    let (controller_did, is_external) = submission.did_document.registration_controller().ok()?;
    if !is_external {
        return None;
    }
    let controller_document = match read_registered_resource_document(state, &controller_did)
        .await
        .ok()
        .flatten()
    {
        Some(document) => document,
        None => {
            let bundle = submission
                .controller_authorization_proof
                .as_ref()
                .filter(|bundle| bundle.controller_did_document.id == controller_did)?;
            validate_controller_index(
                state,
                &bundle.controller_did_document,
                &bundle.challenge.verification_method,
            )
            .await
            .ok()?;
            bundle.controller_did_document.clone()
        }
    };
    let method = find_relationship_method(
        &controller_document,
        VerificationRelationship::CapabilityInvocation,
        None,
    )
    .or_else(|_| {
        find_relationship_method(
            &controller_document,
            VerificationRelationship::AssertionMethod,
            None,
        )
    })
    .ok()?;
    let verification_method = method.id.clone();
    let controller_method_hash =
        controller_method_hash(state, &controller_document, &verification_method).ok()?;
    let authority_binding_hash = hash_json_with_suite(
        state.signing_key.crypto_suite(),
        &json!({
            "resourceDid": submission.resource_did,
            "controllerDid": controller_did,
            "verificationMethod": verification_method,
            "didDocumentHash": submission.did_document_hash,
            "metadataHash": submission.metadata_hash,
            "registrarDid": state.did,
            "purpose": PURPOSE_CONTROLLER_AUTHORIZATION_REGISTRATION
        }),
    )
    .ok()?;
    Some(json!({
        "enabled": true,
        "controllerDid": controller_did,
        "verifiedVerificationMethod": verification_method,
        "verifiedControllerMethodHash": controller_method_hash,
        "verifiedAuthorityBindingHash": authority_binding_hash,
        "verifiedAt": Utc::now(),
        "policyVersion": "registration-credential-access-v1"
    }))
}

fn controller_index_key(controller_did: &str, verification_method: &str) -> String {
    format!(
        "{}--{}",
        did_to_file_name(controller_did),
        did_to_file_name(verification_method)
    )
}

async fn read_controller_index(
    state: &AppState,
    controller_did: &str,
    verification_method: &str,
) -> Result<Option<Value>> {
    let key = controller_index_key(controller_did, verification_method);
    if let Some(sqlite) = &state.sqlite {
        return sqlite
            .read_json("registrar.controller_index", &key)
            .await
            .map_err(Into::into);
    }
    if let Some(postgres) = &state.postgres {
        return postgres
            .read_json("registrar.controller_index", &key)
            .await
            .map_err(Into::into);
    }
    Ok(state.data.read(format!("controller-index/{key}.json")).ok())
}

async fn write_controller_index(state: &AppState, projection: &Value) -> Result<()> {
    let controller_did = projection
        .get("controllerDid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("controller_did_missing"))?;
    let verification_method = projection
        .get("verificationMethod")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("controller_verification_method_missing"))?;
    let key = controller_index_key(controller_did, verification_method);
    if let Some(sqlite) = &state.sqlite {
        sqlite
            .upsert_json("registrar.controller_index", &key, projection)
            .await?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        postgres
            .upsert_json("registrar.controller_index", &key, projection)
            .await?;
        return Ok(());
    }
    state
        .data
        .write(format!("controller-index/{key}.json"), projection)?;
    Ok(())
}

async fn upsert_controller_index_from_document(
    state: &AppState,
    document: &DidDocument,
) -> Result<()> {
    let controller_did = match document.controller.as_ref() {
        Some(oan_core::DidController::Did(did)) if did == &document.id => did.as_str(),
        Some(oan_core::DidController::Dids(dids))
            if dids.len() == 1 && dids.first() == Some(&document.id) =>
        {
            document.id.as_str()
        }
        _ => return Err(anyhow!("controller_self_ownership_missing")),
    };
    let method = document
        .verification_method
        .iter()
        .find(|method| method.id == format!("{controller_did}#key-1"))
        .or_else(|| document.verification_method.first())
        .ok_or_else(|| anyhow!("controller_verification_method_missing"))?;
    let projection = json!({
        "controllerDid": controller_did,
        "verificationMethod": method.id,
        "publicKeyJwk": method.public_key_jwk,
        "methodHash": hash_json_with_suite(CryptoSuite::Ed25519Sha256, method)?,
        "routingCode": controller_did.split(':').nth(2).unwrap_or_default(),
        "status": "active",
        "updatedAt": Utc::now(),
    });
    write_controller_index(state, &projection).await
}

async fn backfill_controller_index(state: &AppState) -> Result<usize> {
    let mut repaired = 0usize;
    let mut scanned = 0usize;
    let mut cursor = state
        .data
        .read(CONTROLLER_INDEX_BACKFILL_STATE_FILE)
        .ok()
        .and_then(|value| serde_json::from_value::<ControllerBackfillState>(value).ok())
        .map(|value| NamespacePageCursor {
            updated_at: value.updated_at,
            record_key: value.record_key,
        });
    loop {
        if scanned >= CONTROLLER_INDEX_BACKFILL_MAX_RECORDS {
            break;
        }
        let remaining = CONTROLLER_INDEX_BACKFILL_MAX_RECORDS - scanned;
        let requested_limit = u32::try_from(remaining)
            .unwrap_or(CONTROLLER_INDEX_BACKFILL_PAGE_SIZE)
            .min(CONTROLLER_INDEX_BACKFILL_PAGE_SIZE);
        let page = if let Some(sqlite) = &state.sqlite {
            sqlite
                .read_namespace_page::<Value>(
                    "registrar.resource_records",
                    cursor.as_ref(),
                    Some(requested_limit),
                    QueryLimits::default(),
                )
                .await?
        } else if let Some(postgres) = &state.postgres {
            postgres
                .read_namespace_page::<Value>(
                    "registrar.resource_records",
                    cursor.as_ref(),
                    Some(requested_limit),
                    QueryLimits::default(),
                )
                .await?
        } else {
            break;
        };
        scanned += page.items.len();
        for record in page.items {
            let document_value = record
                .get("didDocument")
                .cloned()
                .or_else(|| record.get("rootResponse")?.get("didDocument").cloned());
            let Some(document_value) = document_value else {
                continue;
            };
            let Ok(document) = serde_json::from_value::<DidDocument>(document_value) else {
                continue;
            };
            let is_self_controller = matches!(
                document.controller.as_ref(),
                Some(oan_core::DidController::Did(did)) if did == &document.id
            ) || matches!(
                document.controller.as_ref(),
                Some(oan_core::DidController::Dids(dids))
                    if dids.len() == 1 && dids.first() == Some(&document.id)
            );
            if !is_self_controller {
                continue;
            }
            if upsert_controller_index_from_document(state, &document)
                .await
                .is_ok()
            {
                repaired += 1;
            }
        }
        if !page.has_more {
            let _ = std::fs::remove_file(state.data.resolve(CONTROLLER_INDEX_BACKFILL_STATE_FILE));
            break;
        }
        cursor = page.next_cursor;
        if let Some(next) = cursor.as_ref() {
            state.data.write(
                CONTROLLER_INDEX_BACKFILL_STATE_FILE,
                &json!(ControllerBackfillState {
                    updated_at: next.updated_at.clone(),
                    record_key: next.record_key.clone(),
                }),
            )?;
        }
    }
    Ok(repaired)
}

async fn validate_controller_index(
    state: &AppState,
    controller_document: &DidDocument,
    verification_method: &str,
) -> std::result::Result<(), String> {
    let controller_did = controller_document.id.as_str();
    if validate_resource_routing_code(controller_did, &state.did).is_err() {
        return Err("controller_routing_code_mismatch".to_owned());
    }
    let projection = read_controller_index(state, controller_did, verification_method)
        .await
        .map_err(|_| "controller_index_not_ready".to_owned())?
        .ok_or_else(|| "controller_not_registered".to_owned())?;
    if projection.get("status").and_then(Value::as_str) != Some("active") {
        return Err("controller_not_registered".to_owned());
    }
    let method = controller_document
        .verification_method
        .iter()
        .find(|method| method.id == verification_method)
        .ok_or_else(|| "controller_authorization_method_missing".to_owned())?;
    let method_hash = hash_json_with_suite(CryptoSuite::Ed25519Sha256, method)
        .map_err(|_| "controller_verification_method_mismatch".to_owned())?;
    if projection.get("methodHash").and_then(Value::as_str) != Some(method_hash.as_str()) {
        return Err("controller_verification_method_mismatch".to_owned());
    }
    Ok(())
}

fn validate_resource_authorized_domains_for_registrar(
    state: &AppState,
    submission: &ResourceRegistrationSubmission,
) -> std::result::Result<Vec<String>, ApiError> {
    let registrar_document: DidDocument = state
        .data
        .read("did-document.json")
        .map_err(ApiError::internal)?;
    let registrar_domains = registrar_document
        .oan_metadata
        .as_ref()
        .map(|metadata| metadata.authorized_domains.clone())
        .unwrap_or_default();
    let resource_domains = submission
        .did_document
        .oan_metadata
        .as_ref()
        .map(|metadata| metadata.authorized_domains.clone())
        .unwrap_or_default();

    if let Some(metadata_domains) = submission
        .metadata
        .get("authorizedDomains")
        .and_then(Value::as_array)
        .map(|domains| {
            domains
                .iter()
                .map(|domain| {
                    domain
                        .as_str()
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| "invalid_authorized_domains".to_owned())
                })
                .collect::<std::result::Result<Vec<_>, _>>()
        })
        .transpose()
        .map_err(ApiError::bad_request)?
    {
        if metadata_domains != resource_domains {
            return Err(ApiError::bad_request("authorized_domains_mismatch"));
        }
    }

    validate_resource_authorized_domains(&resource_domains, &registrar_domains)
        .map_err(ApiError::bad_request)?;
    Ok(resource_domains)
}

fn validate_authorized_domain_list(domains: &[String]) -> std::result::Result<(), String> {
    if domains.iter().any(|domain| domain == "*") {
        return if domains.len() == 1 {
            Ok(())
        } else {
            Err("invalid_authorized_domains".to_owned())
        };
    }
    for domain in domains {
        if domain.trim().is_empty()
            || domain != domain.trim()
            || domain.contains("..")
            || domain.starts_with('.')
            || domain.ends_with('.')
        {
            return Err("invalid_authorized_domains".to_owned());
        }
    }
    if domains.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("invalid_authorized_domains".to_owned());
    }
    Ok(())
}

fn authorized_domain_covers(granted: &str, requested: &str) -> bool {
    granted == requested
        || requested
            .strip_prefix(granted)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

fn authorized_domains_cover(granted: &[String], requested: &[String]) -> bool {
    if requested.is_empty() {
        return true;
    }
    if granted.iter().any(|domain| domain == "*") {
        return true;
    }
    if granted.is_empty() {
        return false;
    }
    requested.iter().all(|requested_domain| {
        granted
            .iter()
            .any(|granted_domain| authorized_domain_covers(granted_domain, requested_domain))
    })
}

fn validate_resource_authorized_domains(
    resource_domains: &[String],
    registrar_domains: &[String],
) -> std::result::Result<(), String> {
    if resource_domains.is_empty() {
        return Err("resource_domains_required".to_owned());
    }
    validate_authorized_domain_list(resource_domains)?;
    validate_authorized_domain_list(registrar_domains)?;
    if !authorized_domains_cover(registrar_domains, resource_domains) {
        return Err("unauthorized_domains".to_owned());
    }
    Ok(())
}

fn build_resource_verify_and_publish_request_with_raw(
    state: &AppState,
    submission: ResourceRegistrationSubmission,
    raw_did_document: Value,
) -> std::result::Result<ResourceVerifyAndPublishRequest, ApiError> {
    let mut root_submission = submission;
    root_submission.registration_credential = Value::Null;
    let envelope = create_signed_request_envelope(SignedRequestEnvelopeInput {
        request_id: request_id("resource-verify-and-publish"),
        protocol_version: OAN_RESOURCE_PROTOCOL_VERSION.to_owned(),
        purpose: PURPOSE_VERIFY_AND_PUBLISH.to_owned(),
        method: "POST".to_owned(),
        path: PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH.to_owned(),
        aud: state.config.security.upstream.root_did.clone(),
        payload: &root_submission,
        creator: state.did.clone(),
        verification_method: format!("{}#key-1", state.did),
        signing_key: &state.signing_key,
        nonce: request_nonce("resource-verify-and-publish"),
    })
    .map_err(ApiError::internal)?;
    Ok(ResourceVerifyAndPublishRequest {
        registrar_did: state.did.clone(),
        submission: root_submission,
        did_document_raw: Some(raw_did_document),
        upstream_auth: envelope,
    })
}


fn issue_resource_registration_credential(
    state: &AppState,
    submission: &ResourceRegistrationSubmission,
    did_document_hash: &str,
) -> std::result::Result<Value, ApiError> {
    let issued_at = chrono::Utc::now();
    let key_id = format!("{}#key-1", state.did);
    let authorized_domains = submission
        .did_document
        .oan_metadata
        .as_ref()
        .map(|metadata| metadata.authorized_domains.clone())
        .unwrap_or_default();
    let external_identifiers = submission
        .did_document
        .oan_metadata
        .as_ref()
        .map(|metadata| {
            metadata
                .external_identifiers
                .iter()
                .map(|identifier| json!({ "id": identifier.id }))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let subject_type = submission
        .did_document
        .oan_metadata
        .as_ref()
        .map(|metadata| metadata.subject_type.clone())
        .ok_or_else(|| ApiError::bad_request("resource_subject_type_missing"))?;
    let credential_id = format!(
        "urn:oan:credential:resource-registration:{}",
        did_to_file_name(&submission.resource_did).trim_end_matches(".json")
    );
    let subject = ResourceRegistrationCredentialSubject {
        id: submission.resource_did.clone(),
        resource_type: submission.resource_type.clone(),
        subject_type,
        registrar_did: state.did.clone(),
        did_document_hash: did_document_hash.to_owned(),
        metadata_hash: submission.metadata_hash.clone(),
        package_hash: submission.package_hash.clone(),
        package_version: submission.package_version.clone(),
        hash_algorithm: submission.hash_algorithm.clone(),
        authorized_domains,
        external_identifiers: external_identifiers
            .into_iter()
            .filter_map(|value| {
                value
                    .get("id")
                    .and_then(Value::as_str)
                    .map(|id| ExternalIdentifierReference { id: id.to_owned() })
            })
            .collect(),
        lifecycle_state: submission.metadata["lifecycleState"]
            .as_str()
            .unwrap_or("active")
            .to_owned(),
    };
    let mut credential = OanResourceRegistrationCredential {
        context: vec![
            "https://www.w3.org/2018/credentials/v1".to_owned(),
            "https://openagenet.xyz/did-oan-specs/v1".to_owned(),
            "https://w3id.org/security/suites/ed25519-2020/v1".to_owned(),
        ],
        id: Some(credential_id.clone()),
        credential_type: vec![
            "VerifiableCredential".to_owned(),
            "OANResourceRegistrationCredential".to_owned(),
        ],
        issuer: state.did.clone(),
        issuance_date: issued_at,
        expiration_date: None,
        credential_subject: subject,
        credential_status: Some(CredentialStatusReference {
            id: format!(
                "{}/resources/{}/status",
                state
                    .config
                    .server
                    .endpoint
                    .as_deref()
                    .unwrap_or("http://127.0.0.1:8000"),
                did_to_file_name(&submission.resource_did)
            ),
            status_type: "OANResourceRegistrationStatus2026".to_owned(),
            credential_id: Some(credential_id),
            subject_did: Some(submission.resource_did.clone()),
            issuer_did: Some(state.did.clone()),
            status: Some("active".to_owned()),
            updated_at: Some(issued_at),
            extra: Default::default(),
        }),
        credential_schema: None,
        proof: sign_credential(&json!({}), key_id.clone(), key_id, &state.signing_key)
            .map_err(ApiError::internal)?,
    };
    let mut unsigned = serde_json::to_value(&credential).map_err(ApiError::internal)?;
    unsigned
        .as_object_mut()
        .expect("credential serializes as object")
        .remove("proof");
    credential.proof = sign_credential(
        &unsigned,
        format!("{}#key-1", state.did),
        format!("{}#key-1", state.did),
        &state.signing_key,
    )
    .map_err(ApiError::internal)?;
    validate_resource_registration_credential(&credential).map_err(ApiError::internal)?;
    serde_json::to_value(credential).map_err(ApiError::internal)
}

async fn write_resource_record(
    state: &AppState,
    record: &Value,
) -> std::result::Result<(), ApiError> {
    let did = record["resourceDid"]
        .as_str()
        .ok_or_else(|| ApiError::bad_request("resource_did_missing"))?;
    if let Some(sqlite) = &state.sqlite {
        sqlite
            .upsert_json("registrar.resource_records", did, record)
            .await
            .map_err(ApiError::internal)?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        postgres
            .upsert_json("registrar.resource_records", did, record)
            .await
            .map_err(ApiError::internal)?;
        return Ok(());
    }
    state
        .data
        .write(
            format!("resource-records/{}", did_to_file_name(did)),
            record,
        )
        .map_err(ApiError::internal)?;
    Ok(())
}

async fn read_resource_records(state: &AppState) -> Result<Vec<Value>> {
    if let Some(sqlite) = &state.sqlite {
        return sqlite
            .read_namespace("registrar.resource_records")
            .await
            .map_err(Into::into);
    }
    if let Some(postgres) = &state.postgres {
        return postgres
            .read_namespace("registrar.resource_records")
            .await
            .map_err(Into::into);
    }
    Ok(state
        .data
        .read("resource-records/index.json")
        .unwrap_or_else(|_| {
            let mut records = Vec::new();
            if let Ok(entries) =
                std::fs::read_dir(state.config.paths.data_dir.join("resource-records"))
            {
                for entry in entries.flatten() {
                    if entry.path().extension().and_then(|value| value.to_str()) == Some("json") {
                        if let Ok(value) = JsonStore::new(".").read(entry.path()) {
                            records.push(value);
                        }
                    }
                }
            }
            records
        }))
}

async fn read_resource_record(state: &AppState, did: &str) -> Result<Option<Value>> {
    if let Some(sqlite) = &state.sqlite {
        return sqlite
            .read_json("registrar.resource_records", did)
            .await
            .map_err(Into::into);
    }
    if let Some(postgres) = &state.postgres {
        return postgres
            .read_json("registrar.resource_records", did)
            .await
            .map_err(Into::into);
    }
    Ok(state
        .data
        .read(format!("resource-records/{}", did_to_file_name(did)))
        .ok())
}

async fn resource_record_count(state: &AppState) -> Result<usize> {
    if let Some(sqlite) = &state.sqlite {
        return Ok(sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM json_records WHERE namespace = ?",
        )
        .bind("registrar.resource_records")
        .fetch_one(sqlite.pool())
        .await? as usize);
    }
    if let Some(postgres) = &state.postgres {
        return Ok(sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM json_records WHERE namespace = $1",
        )
        .bind("registrar.resource_records")
        .fetch_one(postgres.pool())
        .await? as usize);
    }
    Ok(read_resource_records(state).await?.len())
}

async fn api_status(State(state): State<AppState>) -> ApiResult<Value> {
    let resource_count = resource_record_count(&state)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "registrarDid": state.did,
        "rootEndpoint": state.config.upstream.root_endpoint,
        "resourceRecordCount": resource_count,
        "protocolVersion": OAN_RESOURCE_PROTOCOL_VERSION
    })))
}

async fn api_stats(State(state): State<AppState>) -> ApiResult<Value> {
    registrar_stats_body(&state)
        .await
        .map(Json)
        .map_err(ApiError::internal)
}

async fn registrar_stats_body(state: &AppState) -> Result<Value> {
    // Serialize cache misses so the HTTP endpoint and reporter share one scan.
    let mut cache = state.stats_cache.lock().await;
    if let Some((captured, body)) = cache.as_ref() {
        if captured.elapsed() < std::time::Duration::from_secs(60) {
            return Ok(body.clone());
        }
    }
    let body = compute_registrar_stats_body(state).await?;
    *cache = Some((Instant::now(), body.clone()));
    Ok(body)
}

async fn compute_registrar_stats_body(state: &AppState) -> Result<Value> {
    let generated_at = Utc::now();
    let today = generated_at.date_naive();
    let week_start = today - chrono::Duration::days(today.weekday().num_days_from_monday() as i64);
    let month_start = today.with_day(1).unwrap_or(today);
    let today_text = today.to_string();
    let week_start_text = week_start.to_string();
    let month_start_text = month_start.to_string();
    let (
        resource_record_count,
        controller_count,
        type_counts,
        today_count,
        week_count,
        month_count,
    ) = if let Some(sqlite) = &state.sqlite {
        let row = sqlx::query(
                "SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN json_extract(value_json, '$.resourceType') = 'agent_service' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN json_extract(value_json, '$.resourceType') = 'skill' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN json_extract(value_json, '$.resourceType') = 'mcp_server' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN json_extract(value_json, '$.resourceType') = 'tool_api' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN json_extract(value_json, '$.resourceType') = 'controller' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN substr(json_extract(value_json, '$.submittedAt'), 1, 10) = ? THEN 1 ELSE 0 END),
                    SUM(CASE WHEN substr(json_extract(value_json, '$.submittedAt'), 1, 10) >= ? THEN 1 ELSE 0 END),
                    SUM(CASE WHEN substr(json_extract(value_json, '$.submittedAt'), 1, 10) >= ? THEN 1 ELSE 0 END)
                 FROM json_records
                 WHERE namespace = ?",
            )
            .bind(&today_text)
            .bind(&week_start_text)
            .bind(&month_start_text)
            .bind("registrar.resource_records")
            .fetch_one(sqlite.pool())
            .await?;
        (
            row.get::<i64, _>(0) as usize,
            row.get::<Option<i64>, _>(5).unwrap_or(0),
            [
                row.get::<Option<i64>, _>(1).unwrap_or(0),
                row.get::<Option<i64>, _>(2).unwrap_or(0),
                row.get::<Option<i64>, _>(3).unwrap_or(0),
                row.get::<Option<i64>, _>(4).unwrap_or(0),
            ],
            row.get::<Option<i64>, _>(6).unwrap_or(0),
            row.get::<Option<i64>, _>(7).unwrap_or(0),
            row.get::<Option<i64>, _>(8).unwrap_or(0),
        )
    } else if let Some(postgres) = &state.postgres {
        let row = sqlx::query(
            "SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE value_json::jsonb ->> 'resourceType' = 'agent_service'),
                    COUNT(*) FILTER (WHERE value_json::jsonb ->> 'resourceType' = 'skill'),
                    COUNT(*) FILTER (WHERE value_json::jsonb ->> 'resourceType' = 'mcp_server'),
                    COUNT(*) FILTER (WHERE value_json::jsonb ->> 'resourceType' = 'tool_api'),
                    COUNT(*) FILTER (WHERE value_json::jsonb ->> 'resourceType' = 'controller'),
                    COUNT(*) FILTER (WHERE LEFT(value_json::jsonb ->> 'submittedAt', 10) = $1),
                    COUNT(*) FILTER (WHERE LEFT(value_json::jsonb ->> 'submittedAt', 10) >= $2),
                    COUNT(*) FILTER (WHERE LEFT(value_json::jsonb ->> 'submittedAt', 10) >= $3)
                 FROM json_records
                 WHERE namespace = $4",
        )
        .bind(&today_text)
        .bind(&week_start_text)
        .bind(&month_start_text)
        .bind("registrar.resource_records")
        .fetch_one(postgres.pool())
        .await?;
        (
            row.get::<i64, _>(0) as usize,
            row.get::<i64, _>(5),
            [
                row.get::<i64, _>(1),
                row.get::<i64, _>(2),
                row.get::<i64, _>(3),
                row.get::<i64, _>(4),
            ],
            row.get::<i64, _>(6),
            row.get::<i64, _>(7),
            row.get::<i64, _>(8),
        )
    } else {
        let records = read_resource_records(state).await?;
        let mut type_counts = [0_i64; 5];
        let mut today_count = 0_i64;
        let mut week_count = 0_i64;
        let mut month_count = 0_i64;
        for record in &records {
            accumulate_registrar_stats(
                record,
                &mut type_counts,
                &mut today_count,
                &mut week_count,
                &mut month_count,
                (today, week_start, month_start),
            );
        }
        (
            records.len(),
            type_counts[4],
            [
                type_counts[0],
                type_counts[1],
                type_counts[2],
                type_counts[3],
            ],
            today_count,
            week_count,
            month_count,
        )
    };
    Ok(json!({
        "registrarDid": state.did,
        "generatedAt": generated_at.to_rfc3339(),
        "windowTimezone": "UTC",
        "resourceRecordCount": resource_record_count,
        "controllerCount": controller_count,
        "agentServiceCount": type_counts[0],
        "skillCount": type_counts[1],
        "mcpServerCount": type_counts[2],
        "toolApiCount": type_counts[3],
        "todayRegistrationCount": today_count,
        "weekRegistrationCount": week_count,
        "monthRegistrationCount": month_count,
    }))
}

fn accumulate_registrar_stats(
    record: &Value,
    type_counts: &mut [i64; 5],
    today_count: &mut i64,
    week_count: &mut i64,
    month_count: &mut i64,
    (today, week_start, month_start): (chrono::NaiveDate, chrono::NaiveDate, chrono::NaiveDate),
) {
    match record.get("resourceType").and_then(Value::as_str) {
        Some("agent_service") => type_counts[0] += 1,
        Some("skill") => type_counts[1] += 1,
        Some("mcp_server") => type_counts[2] += 1,
        Some("tool_api") => type_counts[3] += 1,
        Some("controller") => type_counts[4] += 1,
        _ => {}
    }
    let Some(submitted_at) = record.get("submittedAt").and_then(Value::as_str) else {
        return;
    };
    let Ok(submitted_at) = DateTime::parse_from_rfc3339(submitted_at) else {
        return;
    };
    let submitted_day = submitted_at.with_timezone(&Utc).date_naive();
    if submitted_day == today {
        *today_count += 1;
    }
    if submitted_day >= week_start {
        *week_count += 1;
    }
    if submitted_day >= month_start {
        *month_count += 1;
    }
}

async fn registrar_stats_report_loop(state: AppState) {
    loop {
        if let Err(err) = report_registrar_stats_once(&state).await {
            eprintln!("registrar stats report failed: {err}");
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(
            state.config.stats_report.interval_seconds,
        ))
        .await;
    }
}

async fn report_registrar_stats_once(state: &AppState) -> Result<()> {
    let config = &state.config.stats_report;
    let stats = registrar_stats_body(state).await?;
    let endpoint = config
        .endpoint
        .as_deref()
        .ok_or_else(|| anyhow!("stats_report.endpoint is required"))?;
    let token = config
        .token
        .as_deref()
        .ok_or_else(|| anyhow!("stats_report.token is required"))?;
    let payload = json!({
        "nodeId": config
            .node_id
            .as_deref()
            .ok_or_else(|| anyhow!("stats_report.node_id is required"))?,
        "role": "registrar",
        "status": "online",
        "generatedAt": stats["generatedAt"],
        "resourceTotals": {
            "registeredResources": stats["resourceRecordCount"].as_u64().unwrap_or(0)
                .saturating_sub(stats["controllerCount"].as_u64().unwrap_or(0)),
            "totalControllers": stats["controllerCount"]
        },
        "resourcesByType": {
            "agentService": stats["agentServiceCount"],
            "skill": stats["skillCount"],
            "mcpServer": stats["mcpServerCount"],
            "toolApi": stats["toolApiCount"]
        },
        "registrationWindows": {
            "today": stats["todayRegistrationCount"],
            "thisWeek": stats["weekRegistrationCount"],
            "thisMonth": stats["monthRegistrationCount"]
        }
    });
    let response = state
        .client
        .post(endpoint)
        .bearer_auth(token)
        .json(&payload)
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("homepage returned {status}: {body}"));
    }
    Ok(())
}

async fn api_root_authorization(State(state): State<AppState>) -> ApiResult<Value> {
    let response = state
        .client
        .get(format!(
            "{}/root/registrars/{}",
            state.config.upstream.root_endpoint.trim_end_matches('/'),
            state.did
        ))
        .send()
        .await;
    match response {
        Ok(response) if response.status().is_success() => {
            let body: Value = response.json().await.unwrap_or_else(|_| json!({}));
            Ok(Json(json!({
                "registrarDid": state.did,
                "rootEndpoint": state.config.upstream.root_endpoint,
                "rootReachable": true,
                "authorization": body
            })))
        }
        Ok(response) => Ok(Json(json!({
            "registrarDid": state.did,
            "rootEndpoint": state.config.upstream.root_endpoint,
            "rootReachable": true,
            "status": "unknown",
            "rootStatusCode": response.status().as_u16()
        }))),
        Err(err) => Ok(Json(json!({
            "registrarDid": state.did,
            "rootEndpoint": state.config.upstream.root_endpoint,
            "rootReachable": false,
            "error": err.to_string()
        }))),
    }
}

async fn api_resources(
    State(state): State<AppState>,
    Query(query): Query<ResourceListQuery>,
) -> ApiResult<Value> {
    let limit = query.limit.unwrap_or(REGISTRAR_DEFAULT_PAGE_SIZE);
    if limit == 0 || limit > REGISTRAR_MAX_PAGE_SIZE {
        return Err(ApiError::bad_request("invalid_resource_page_limit"));
    }
    let after_did = query.after_did.as_deref().unwrap_or("");
    let mut items = Vec::new();
    let has_more;
    let mut next_did = None;
    let mut page_bytes = 0_usize;
    if let Some(sqlite) = &state.sqlite {
        let mut rows = sqlx::query(
            "SELECT record_key, value_json FROM json_records
             WHERE namespace = ? AND record_key > ?
             ORDER BY record_key LIMIT ?",
        )
        .bind("registrar.resource_records")
        .bind(after_did)
        .bind(i64::from(limit))
        .fetch(sqlite.pool());
        while let Some(row) = rows.try_next().await.map_err(ApiError::internal)? {
            let did = row.get::<String, _>(0);
            next_did = Some(did);
            let value_json = row.get::<String, _>(1);
            items.push(public_resource_record_projection_from_json(
                &value_json,
                &mut page_bytes,
            )?);
        }
        let probe_after = next_did.as_deref().unwrap_or(after_did);
        has_more = sqlx::query(
            "SELECT 1 FROM json_records
             WHERE namespace = ? AND record_key > ?
             LIMIT 1",
        )
        .bind("registrar.resource_records")
        .bind(probe_after)
        .fetch_optional(sqlite.pool())
        .await
        .map_err(ApiError::internal)?
        .is_some();
    } else if let Some(postgres) = &state.postgres {
        let mut rows = sqlx::query(
            "SELECT record_key, value_json::text FROM json_records
             WHERE namespace = $1 AND record_key > $2
             ORDER BY record_key LIMIT $3",
        )
        .bind("registrar.resource_records")
        .bind(after_did)
        .bind(i64::from(limit))
        .fetch(postgres.pool());
        while let Some(row) = rows.try_next().await.map_err(ApiError::internal)? {
            let did = row.get::<String, _>(0);
            next_did = Some(did);
            let value_json = row.get::<String, _>(1);
            items.push(public_resource_record_projection_from_json(
                &value_json,
                &mut page_bytes,
            )?);
        }
        let probe_after = next_did.as_deref().unwrap_or(after_did);
        has_more = sqlx::query(
            "SELECT 1 FROM json_records
             WHERE namespace = $1 AND record_key > $2
             LIMIT 1",
        )
        .bind("registrar.resource_records")
        .bind(probe_after)
        .fetch_optional(postgres.pool())
        .await
        .map_err(ApiError::internal)?
        .is_some();
    } else {
        let records = read_resource_records(&state)
            .await
            .map_err(ApiError::internal)?;
        let mut records = records
            .iter()
            .filter_map(|record| {
                let did = record.get("resourceDid")?.as_str()?;
                (did > after_did).then_some((did.to_owned(), record))
            })
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.0.cmp(&right.0));
        has_more = records.len() > limit as usize;
        records.truncate(limit as usize);
        for (did, record) in records {
            next_did = Some(did);
            let value_json = serde_json::to_string(record).map_err(ApiError::internal)?;
            items.push(public_resource_record_projection_from_json(
                &value_json,
                &mut page_bytes,
            )?);
        }
    }
    if !has_more {
        next_did = None;
    }
    Ok(Json(json!({
        "items": items,
        "count": items.len(),
        "afterDid": if after_did.is_empty() { Value::Null } else { json!(after_did) },
        "nextDid": next_did,
        "hasMore": has_more
    })))
}

fn public_resource_record_projection_from_json(
    value_json: &str,
    page_bytes: &mut usize,
) -> std::result::Result<Value, ApiError> {
    let record_bytes = value_json.len();
    if record_bytes > REGISTRAR_MAX_RECORD_BYTES {
        return Err(ApiError::bad_request("resource_record_too_large"));
    }
    *page_bytes = page_bytes.saturating_add(record_bytes);
    if *page_bytes > REGISTRAR_MAX_PAGE_BYTES {
        return Err(ApiError::bad_request("resource_page_too_large"));
    }
    let record: Value = serde_json::from_str(value_json).map_err(ApiError::internal)?;
    Ok(public_resource_record_projection(&record))
}

async fn api_resource_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    let record = read_resource_record(&state, &did)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("resource_not_found"))?;
    Ok(Json(json!({
        "resourceDid": did,
        "record": public_resource_record_projection(&record)
    })))
}

async fn api_registration_credential_status(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    let record = read_resource_record(&state, &did)
        .await
        .map_err(ApiError::internal)?;
    let Some(record) = record else {
        return Ok(Json(json!({
            "issuerDid": state.did,
            "credentialId": format!("urn:oan:credential:resource-registration:{}", did_to_file_name(&did).trim_end_matches(".json")),
            "subjectDid": did,
            "status": "unknown",
            "reason": "not_found",
            "observedAt": Utc::now(),
        })));
    };
    let status = record
        .get("rootResponse")
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("active");
    Ok(Json(json!({
        "issuerDid": state.did,
        "credentialId": record.pointer("/registrationCredential/id"),
        "subjectDid": did,
        "status": status,
        "observedAt": record.get("submittedAt").cloned().unwrap_or_else(|| json!(Utc::now())),
    })))
}

fn public_resource_record_projection(record: &Value) -> Value {
    let mut projection = serde_json::Map::new();
    for field in [
        "resourceDid",
        "resourceType",
        "packageVersion",
        "didDocumentHash",
        "metadataHash",
        "packageHash",
        "authorizedDomains",
        "submittedAt",
    ] {
        if let Some(value) = record.get(field) {
            projection.insert(field.to_owned(), value.clone());
        }
    }
    if let Some(status) = record
        .get("rootResponse")
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
    {
        projection.insert("rootStatus".to_owned(), json!(status));
    }
    Value::Object(projection)
}

async fn api_registration_credential(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
    Json(request): Json<RegistrationCredentialQueryRequest>,
) -> std::result::Result<Response, ApiError> {
    let record = read_resource_record(&state, &did)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("resource_not_found"))?;
    let registration_credential = record
        .get("registrationCredential")
        .cloned()
        .ok_or_else(|| ApiError::forbidden("registration_credential_access_denied"))?;
    verify_registration_credential_query(&state, &did, &record, &request)?;
    let body = json!({
        "resourceDid": did,
        "controllerDid": request.challenge.controller_did,
        "registrationCredential": registration_credential
    });
    Ok((
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(body),
    )
        .into_response())
}

fn verify_registration_credential_query(
    state: &AppState,
    resource_did: &str,
    record: &Value,
    request: &RegistrationCredentialQueryRequest,
) -> std::result::Result<(), ApiError> {
    let challenge = &request.challenge;
    if challenge.method != "POST"
        || challenge.path != registration_credential_query_path(resource_did)
        || challenge.resource_did != resource_did
        || challenge.purpose != PURPOSE_REGISTRATION_CREDENTIAL_QUERY
        || challenge.aud != state.did
        || challenge.protocol_version != PROTOCOL_REGISTRATION_CREDENTIAL_QUERY_V1
        || challenge.request_nonce.trim().is_empty()
    {
        return Err(ApiError::bad_request(
            "invalid_registration_credential_query",
        ));
    }
    if challenge.request_timestamp
        > Utc::now() + Duration::seconds(REGISTRATION_CREDENTIAL_QUERY_MAX_CLOCK_SKEW_SECONDS)
        || Utc::now()
            > challenge.request_timestamp
                + Duration::seconds(REGISTRATION_CREDENTIAL_QUERY_MAX_CLOCK_SKEW_SECONDS)
    {
        return Err(ApiError::bad_request(
            "registration_credential_query_expired",
        ));
    }
    let access = record
        .get("registrationCredentialAccess")
        .and_then(Value::as_object)
        .ok_or_else(|| ApiError::forbidden("registration_credential_access_denied"))?;
    if access.get("enabled").and_then(Value::as_bool) != Some(true) {
        return Err(ApiError::forbidden("registration_credential_access_denied"));
    }
    if access
        .get("controllerDid")
        .and_then(Value::as_str)
        .map(|value| value != challenge.controller_did)
        .unwrap_or(true)
    {
        return Err(ApiError::forbidden("registration_credential_access_denied"));
    }
    if access
        .get("verifiedVerificationMethod")
        .and_then(Value::as_str)
        .map(|value| value != challenge.verification_method)
        .unwrap_or(true)
    {
        return Err(ApiError::forbidden("registration_credential_access_denied"));
    }
    if request.controller_did_document.id != challenge.controller_did {
        return Err(ApiError::unauthorized("invalid_controller_signature"));
    }
    let method = find_relationship_method(
        &request.controller_did_document,
        VerificationRelationship::CapabilityInvocation,
        Some(&challenge.verification_method),
    )
    .or_else(|_| {
        find_relationship_method(
            &request.controller_did_document,
            VerificationRelationship::Authentication,
            Some(&challenge.verification_method),
        )
    })
    .or_else(|_| {
        find_relationship_method(
            &request.controller_did_document,
            VerificationRelationship::AssertionMethod,
            Some(&challenge.verification_method),
        )
    })
    .map_err(|_| ApiError::unauthorized("invalid_controller_signature"))?;
    let verifying_key = verifying_key_from_method(method)
        .map_err(|_| ApiError::unauthorized("invalid_controller_signature"))?;
    let expected_method_hash = access
        .get("verifiedControllerMethodHash")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::forbidden("registration_credential_access_denied"))?;
    let actual_method_hash = hash_json_with_suite(state.signing_key.crypto_suite(), method)
        .map_err(|_| ApiError::unauthorized("invalid_controller_signature"))?;
    if actual_method_hash != expected_method_hash {
        return Err(ApiError::forbidden("registration_credential_access_denied"));
    }
    verify_payload_with_proof(challenge, &request.proof, &verifying_key)
        .map_err(|_| ApiError::unauthorized("invalid_controller_signature"))?;
    verify_and_store_nonce(
        &state.config.paths.registration_credential_query_nonce_file,
        &challenge.request_nonce,
        challenge.request_timestamp,
        Utc::now(),
        REGISTRATION_CREDENTIAL_QUERY_NONCE_TTL_SECONDS,
    )
    .map_err(|err| {
        if err.to_string().contains("nonce_replayed") {
            ApiError::forbidden("registration_credential_query_replay")
        } else {
            ApiError::bad_request("invalid_registration_credential_query")
        }
    })?;
    Ok(())
}

fn registration_credential_query_path(resource_did: &str) -> String {
    format!(
        "/resources/{}/registration-credential",
        percent_encode_path_segment(resource_did)
    )
}

fn controller_method_hash(
    state: &AppState,
    controller_document: &DidDocument,
    verification_method: &str,
) -> std::result::Result<String, ApiError> {
    let method = controller_document
        .verification_method
        .iter()
        .find(|method| method.id == verification_method)
        .ok_or_else(|| ApiError::bad_request("controller_authorization_method_missing"))?;
    hash_json_with_suite(state.signing_key.crypto_suite(), method).map_err(ApiError::internal)
}

fn percent_encode_path_segment(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char)
            }
            _ => output.push_str(&format!("%{byte:02X}")),
        }
    }
    output
}

async fn api_capability_tree() -> ApiResult<Value> {
    let tree = CapabilityTagTree::load_from_path("../../docs/capability-tree-v1.json").unwrap_or(
        CapabilityTagTree {
            version: 1,
            tags: vec![],
            tree: vec![],
        },
    );
    Ok(Json(json!(tree)))
}

async fn api_suggest_tags(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> ApiResult<Value> {
    let text = payload["description"]
        .as_str()
        .or_else(|| payload["query"].as_str())
        .unwrap_or("");
    let input = RegistrationSuggestionInput {
        resource_type: None,
        name: payload["name"].as_str().unwrap_or("").to_owned(),
        description: text.to_owned(),
        endpoint: payload["endpoint"].as_str().map(ToOwned::to_owned),
        manifest_text: payload["manifestText"].as_str().map(ToOwned::to_owned),
        schema_text: payload["schemaText"].as_str().map(ToOwned::to_owned),
        locale: payload["locale"].as_str().map(ToOwned::to_owned),
    };
    let result = state
        .recommender
        .suggest_registration_metadata(input, registration_suggestion_context(&state)?)
        .map_err(|err| ApiError::bad_request(err.to_string()))?;
    let suggestions = result
        .capability_tags
        .iter()
        .map(|tag| tag.value.clone())
        .collect::<Vec<_>>();
    Ok(Json(
        json!({ "suggestions": suggestions, "capabilityTags": result.capability_tags }),
    ))
}

async fn api_normalize_tags(Json(payload): Json<Value>) -> ApiResult<Value> {
    let tags = payload["tags"]
        .as_array()
        .or_else(|| payload["capabilityTags"].as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let normalized = normalize_capability_tags(&tags);
    Ok(Json(json!({
        "tags": normalized,
        "capabilityTags": normalized
    })))
}

async fn api_registration_domain_catalog(State(state): State<AppState>) -> ApiResult<Value> {
    let registrar_domains = registrar_authorized_domains(&state)?;
    let domains = state
        .recommender
        .taxonomy()
        .domains
        .iter()
        .filter(|domain| {
            domain_covered_by_scope(&state, &domain.id, &registrar_domains).unwrap_or(false)
        })
        .map(|domain| {
            json!({
                "id": domain.id,
                "label": domain.label,
                "aliases": domain.aliases,
                "selectable": true
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "registrarDid": state.did,
        "authorizedDomains": registrar_domains,
        "catalogVersion": state.recommender.taxonomy().version,
        "snapshotHash": state.recommender.taxonomy().snapshot_hash,
        "domains": domains
    })))
}

async fn api_registration_suggestions(
    State(state): State<AppState>,
    Json(payload): Json<RegistrationSuggestionInput>,
) -> ApiResult<Value> {
    let result = state
        .recommender
        .suggest_registration_metadata(payload, registration_suggestion_context(&state)?)
        .map_err(|err| ApiError::bad_request(err.to_string()))?;
    Ok(Json(
        serde_json::to_value(result).map_err(ApiError::internal)?,
    ))
}

fn registration_suggestion_context(
    state: &AppState,
) -> std::result::Result<RegistrationSuggestionContext, ApiError> {
    Ok(RegistrationSuggestionContext {
        registrar_did: state.did.clone(),
        allowed_domains: registrar_authorized_domains(state)?,
        max_authorized_domain_candidates: 8,
        max_capability_tag_candidates: 12,
    })
}

fn registrar_authorized_domains(state: &AppState) -> std::result::Result<Vec<String>, ApiError> {
    let registrar_document: DidDocument = state
        .data
        .read("did-document.json")
        .map_err(ApiError::internal)?;
    Ok(registrar_document
        .oan_metadata
        .as_ref()
        .map(|metadata| metadata.authorized_domains.clone())
        .unwrap_or_default())
}

fn domain_covered_by_scope(
    state: &AppState,
    domain: &str,
    scope: &[String],
) -> std::result::Result<bool, ApiError> {
    if scope.iter().any(|item| item == "*") {
        return Ok(true);
    }
    Ok(state
        .recommender
        .taxonomy()
        .covers_authorized_domains(&[domain.to_owned()], scope))
}

