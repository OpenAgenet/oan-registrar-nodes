// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use anyhow::Result;
use axum::{
    extract::{Path as AxumPath, State},
    http::{HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use oan_core::{CapabilityTagTree, CryptoSuite, DidDocument};
use oan_credentials::sign_credential;
use oan_crypto::{hash_json_with_suite, signing_key_from_bytes, SigningKey};
use oan_protocol::{
    HealthResponse, ResourceRegistrationSubmission, ResourceVerifyAndPublishRequest,
    OAN_RESOURCE_PROTOCOL_VERSION, PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
    PURPOSE_VERIFY_AND_PUBLISH,
};
use oan_service_security::{
    create_signed_request_envelope, request_id, request_nonce, SignedRequestEnvelopeInput,
};
use oan_storage::{
    did_to_file_name, DatabaseBackend, DatabaseConfig, JsonStore, PostgresJsonStore,
    SqliteJsonStore,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};

#[derive(Clone, Debug, Deserialize)]
struct Config {
    server: ServerConfig,
    #[serde(default)]
    cors: CorsConfig,
    #[serde(default)]
    security: SecurityConfig,
    upstream: UpstreamConfig,
    paths: PathConfig,
}

#[derive(Clone, Debug, Deserialize)]
struct ServerConfig {
    host: String,
    port: u16,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct CorsConfig {
    #[serde(default)]
    allowed_origins: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct UpstreamConfig {
    root_endpoint: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct SecurityConfig {
    #[serde(default)]
    upstream: UpstreamSecurityConfig,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct UpstreamSecurityConfig {
    #[serde(default = "default_root_did")]
    root_did: String,
}

#[derive(Clone, Debug, Deserialize)]
struct PathConfig {
    data_dir: PathBuf,
    #[serde(default = "default_records_dir")]
    records_dir: PathBuf,
    #[serde(default = "default_keys_dir")]
    keys_dir: PathBuf,
    #[serde(default)]
    database_url: Option<String>,
}

fn default_records_dir() -> PathBuf {
    PathBuf::from("../../data/registrar/resource-records")
}

fn default_keys_dir() -> PathBuf {
    PathBuf::from("../../data/registrar/keys")
}

fn default_root_did() -> String {
    "did:oan:INRT:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz".to_owned()
}

#[derive(Clone)]
struct AppState {
    data: JsonStore,
    config: Config,
    did: String,
    signing_key: SigningKey,
    sqlite: Option<SqliteJsonStore>,
    postgres: Option<PostgresJsonStore>,
    client: reqwest::Client,
}

#[derive(Clone, Debug, Deserialize)]
struct DevKeyFile {
    algorithm: String,
    #[serde(rename = "privateKeyJwk")]
    private_key_jwk: PrivateKeyJwk,
}

#[derive(Clone, Debug, Deserialize)]
struct PrivateKeyJwk {
    d: String,
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

fn crypto_suite_from_algorithm(value: &str) -> Result<CryptoSuite> {
    match value {
        "Ed25519" => Ok(CryptoSuite::Ed25519Sha256),
        "SM2" => Ok(CryptoSuite::Sm2Sm3),
        other => Err(anyhow::anyhow!("unsupported_algorithm: {other}")),
    }
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
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

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "services/registrar-node/config.example.toml".to_owned());
    let config = load_config(config_path)?;
    let did_doc: DidDocument = JsonStore::new(&config.paths.data_dir).read("did-document.json")?;
    let key: DevKeyFile = JsonStore::new(".").read(config.paths.keys_dir.join("keypair.json"))?;
    let crypto_suite = crypto_suite_from_algorithm(&key.algorithm)?;
    let signing_key = signing_key_from_bytes(
        crypto_suite,
        &URL_SAFE_NO_PAD.decode(key.private_key_jwk.d)?,
    )?;
    let (sqlite, postgres) = match config.paths.database_url.as_deref() {
        Some(url) if !url.is_empty() => {
            let database = DatabaseConfig::parse(url)?;
            match database.backend() {
                DatabaseBackend::Sqlite => {
                    let sqlite = SqliteJsonStore::connect(url).await?;
                    (Some(sqlite), None)
                }
                DatabaseBackend::Postgres => {
                    let postgres = PostgresJsonStore::connect(url).await?;
                    (None, Some(postgres))
                }
            }
        }
        _ => (None, None),
    };
    let state = AppState {
        data: JsonStore::new(&config.paths.data_dir),
        config: config.clone(),
        did: did_doc.id,
        signing_key,
        sqlite,
        postgres,
        client: reqwest::Client::new(),
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/registrar/did", get(registrar_did_document))
        .route("/resources/register", post(register_resource))
        .route("/resources/submit", post(register_resource))
        .route("/registrar/status", get(api_status))
        .route("/registrar/root-authorization", get(api_root_authorization))
        .route("/resources", get(api_resources))
        .route("/resources/{did}", get(api_resource_detail))
        .route("/capability-tree", get(api_capability_tree))
        .route("/capability-tags/suggest", post(api_suggest_tags))
        .layer(build_cors_layer(&config.cors)?)
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port).parse()?;
    println!("registrar-node listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn load_config(path: String) -> Result<Config> {
    let path = PathBuf::from(path);
    let mut config: Config = toml::from_str(&std::fs::read_to_string(&path)?)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    config.paths.data_dir = resolve_relative(base, &config.paths.data_dir);
    config.paths.records_dir = resolve_relative(base, &config.paths.records_dir);
    config.paths.keys_dir = resolve_relative(base, &config.paths.keys_dir);
    if let Some(database_url) = config.paths.database_url.as_mut() {
        *database_url = resolve_database_url(base, database_url);
    }
    Ok(config)
}

fn resolve_relative(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn resolve_database_url(base: &Path, url: &str) -> String {
    let Some(raw_path) = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))
    else {
        return url.to_owned();
    };
    let resolved = resolve_relative(base, Path::new(raw_path));
    format!("sqlite:{}", resolved.display())
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

async fn register_resource(
    State(state): State<AppState>,
    Json(submission): Json<ResourceRegistrationSubmission>,
) -> ApiResult<Value> {
    submission.validate_shape().map_err(ApiError::bad_request)?;
    let request = build_resource_verify_and_publish_request(&state, submission.clone())?;
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
    let did_document_hash =
        hash_json_with_suite(state.signing_key.crypto_suite(), &submission.did_document)
            .map_err(ApiError::internal)?;
    let registration_credential =
        issue_resource_registration_credential(&state, &submission, &did_document_hash)?;
    let record = json!({
        "resourceDid": submission.resource_did,
        "resourceType": submission.resource_type,
        "packageVersion": submission.package_version,
        "didDocumentHash": did_document_hash,
        "metadataHash": submission.metadata_hash,
        "packageHash": submission.package_hash,
        "registrationCredential": registration_credential,
        "rootResponse": body,
        "submittedAt": chrono::Utc::now()
    });
    write_resource_record(&state, &record).await?;
    Ok(Json(json!({
        "status": "submitted",
        "resourceDid": record["resourceDid"],
        "resourceType": record["resourceType"],
        "registrationCredential": record["registrationCredential"],
        "rootResponse": record["rootResponse"]
    })))
}

fn build_resource_verify_and_publish_request(
    state: &AppState,
    submission: ResourceRegistrationSubmission,
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
    let mut credential = json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://openagenet.org/credentials/v1"
        ],
        "id": format!("urn:oan:credential:resource-registration:{}", did_to_file_name(&submission.resource_did).trim_end_matches(".json")),
        "type": [
            "VerifiableCredential",
            "OANResourceRegistrationCredential"
        ],
        "issuer": state.did,
        "issuanceDate": issued_at,
        "credentialSubject": {
            "id": submission.resource_did,
            "resourceDid": submission.resource_did,
            "resourceType": submission.resource_type,
            "didDocumentHash": did_document_hash,
            "metadataHash": submission.metadata_hash,
            "packageHash": submission.package_hash,
            "packageVersion": submission.package_version,
            "hashAlgorithm": submission.hash_algorithm,
            "lifecycleState": submission.metadata["lifecycleState"].as_str().unwrap_or("active")
        },
        "credentialStatus": {
            "type": "OANResourceRegistrationStatus",
            "status": "active"
        }
    });
    let proof = sign_credential(&credential, key_id.clone(), key_id, &state.signing_key)
        .map_err(ApiError::internal)?;
    credential["proof"] = serde_json::to_value(proof).map_err(ApiError::internal)?;
    Ok(credential)
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

async fn api_status(State(state): State<AppState>) -> ApiResult<Value> {
    let records = read_resource_records(&state)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "registrarDid": state.did,
        "rootEndpoint": state.config.upstream.root_endpoint,
        "resourceRecordCount": records.len(),
        "protocolVersion": OAN_RESOURCE_PROTOCOL_VERSION
    })))
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

async fn api_resources(State(state): State<AppState>) -> ApiResult<Value> {
    let records = read_resource_records(&state)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "items": records, "count": records.len() })))
}

async fn api_resource_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    let record = read_resource_record(&state, &did)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "resourceDid": did, "record": record })))
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

async fn api_suggest_tags(Json(payload): Json<Value>) -> ApiResult<Value> {
    let text = payload["description"]
        .as_str()
        .or_else(|| payload["query"].as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let suggestions = if text.contains("contract") || text.contains("legal") {
        vec!["legal.contract.review"]
    } else if text.contains("mcp") {
        vec!["protocol.mcp"]
    } else if text.contains("api") || text.contains("tool") {
        vec!["tool.api"]
    } else {
        vec!["general.resource"]
    };
    Ok(Json(json!({ "suggestions": suggestions })))
}

