// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use super::runtime_config::RuntimeConfig;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    pub database: oan_config::DatabaseConfig,
    pub server: ServerConfig,
    #[serde(default)]
    pub cors: CorsConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub stats_report: StatsReportConfig,
    pub upstream: UpstreamConfig,
    pub paths: PathConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServerConfig {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub endpoint: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CorsConfig {
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UpstreamConfig {
    pub root_endpoint: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SecurityConfig {
    #[serde(default)]
    pub upstream: UpstreamSecurityConfig,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UpstreamSecurityConfig {
    #[serde(default = "default_root_did")]
    pub root_did: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StatsReportConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default = "default_stats_report_interval_seconds")]
    pub interval_seconds: u64,
}

impl Default for StatsReportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            node_id: None,
            endpoint: None,
            token: None,
            interval_seconds: default_stats_report_interval_seconds(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PathConfig {
    pub data_dir: PathBuf,
    #[serde(default = "default_records_dir")]
    pub records_dir: PathBuf,
    #[serde(default = "default_identity_file")]
    pub identity_file: PathBuf,
    #[serde(default = "default_controller_authorization_nonce_file")]
    pub controller_authorization_nonce_file: PathBuf,
    #[serde(default = "default_registration_credential_query_nonce_file")]
    pub registration_credential_query_nonce_file: PathBuf,
    #[serde(default)]
    pub database_url: Option<String>,
}

pub(super) fn default_records_dir() -> PathBuf {
    PathBuf::from("../../data/registrar/resource-records")
}

pub(super) fn default_identity_file() -> PathBuf {
    PathBuf::from("../../data/registrar/identity.json")
}

pub(super) fn default_controller_authorization_nonce_file() -> PathBuf {
    PathBuf::from("../../data/registrar/controller-authorization-nonces.json")
}

pub(super) fn default_registration_credential_query_nonce_file() -> PathBuf {
    PathBuf::from("../../data/registrar/registration-credential-query-nonces.json")
}

pub(super) fn default_root_did() -> String {
    "did:oan:QwErT:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz".to_owned()
}

pub(super) fn default_stats_report_interval_seconds() -> u64 {
    60
}

pub(super) fn load_config_details(
    path: String,
) -> Result<(Config, std::collections::BTreeMap<String, String>)> {
    let path = oan_config::absolute(Path::new(&path))?;
    let loaded =
        oan_config::load::<Config>(&path, PREFIX, FIELDS, &oan_config::environment(), true)?;
    let mut config = loaded.value;
    for warning in &loaded.warnings {
        eprintln!("{warning}");
    }
    config.runtime.validate()?;
    if config.server.host.trim().is_empty() {
        return Err(anyhow::anyhow!("server.host is required"));
    }
    if let Some(url) = config
        .paths
        .database_url
        .as_deref()
        .filter(|u| !u.is_empty())
    {
        oan_storage::DatabaseConfig::parse(url)
            .map_err(|_| anyhow::anyhow!("invalid paths.database_url (value hidden)"))?;
    }
    config
        .database
        .pool
        .resolve(config.paths.database_url.as_deref())?;
    oan_config::validate_http_endpoint("upstream.root_endpoint", &config.upstream.root_endpoint)?;
    validate_paths(&serde_json::to_value(&config)?)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    config.paths.data_dir = resolve_relative(base, &config.paths.data_dir);
    config.paths.records_dir = resolve_relative(base, &config.paths.records_dir);
    config.paths.identity_file = resolve_relative(base, &config.paths.identity_file);
    config.paths.controller_authorization_nonce_file =
        resolve_relative(base, &config.paths.controller_authorization_nonce_file);
    config.paths.registration_credential_query_nonce_file =
        resolve_relative(base, &config.paths.registration_credential_query_nonce_file);
    if let Some(database_url) = config.paths.database_url.as_mut() {
        *database_url = resolve_database_url(base, database_url);
    }
    super::validate_stats_report_config(&config.stats_report)?;
    Ok((config, loaded.sources))
}

pub(super) fn resolve_relative(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        oan_config::absolute(path).expect("absolute path normalization")
    } else {
        // base is made absolute during configuration loading.
        oan_config::absolute(&base.join(path)).expect("configuration directory resolved")
    }
}

pub(super) fn resolve_database_url(base: &Path, url: &str) -> String {
    let Some(raw_path) = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))
    else {
        return url.to_owned();
    };
    let resolved = resolve_relative(base, Path::new(raw_path));
    format!("sqlite:{}", resolved.display())
}

const PREFIX: &str = "OAN_REGISTRAR";
const FIELDS: &[oan_config::Field] = &[
    oan_config::Field {
        path: "server.host",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "server.port",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "server.endpoint",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "cors.allowed_origins",
        kind: oan_config::Kind::List,
    },
    oan_config::Field {
        path: "security.upstream.root_did",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "stats_report.enabled",
        kind: oan_config::Kind::Bool,
    },
    oan_config::Field {
        path: "stats_report.node_id",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "stats_report.endpoint",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "stats_report.token",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "stats_report.interval_seconds",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "upstream.root_endpoint",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "paths.data_dir",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "paths.records_dir",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "paths.identity_file",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "paths.controller_authorization_nonce_file",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "paths.registration_credential_query_nonce_file",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "paths.database_url",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "runtime.tokio.worker_threads",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "runtime.tokio.thread_stack_size_mib",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "runtime.tokio.max_blocking_threads",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "runtime.did_verification.worker_count",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "runtime.did_verification.queue_capacity",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "runtime.did_verification.worker_stack_size_mib",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "database.pool.max_connections",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "database.pool.acquire_timeout_seconds",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "database.pool.idle_timeout_seconds",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "database.pool.max_lifetime_seconds",
        kind: oan_config::Kind::U64,
    },
];

fn validate_paths(config: &serde_json::Value) -> Result<()> {
    if config
        .pointer("/paths/data_dir")
        .and_then(serde_json::Value::as_str)
        .is_some_and(str::is_empty)
    {
        return Err(anyhow::anyhow!("paths.data_dir must not be empty"));
    }
    if config
        .pointer("/paths/identity_file")
        .and_then(serde_json::Value::as_str)
        .is_some_and(str::is_empty)
    {
        return Err(anyhow::anyhow!("paths.identity_file must not be empty"));
    }
    if config
        .pointer("/paths/records_dir")
        .and_then(serde_json::Value::as_str)
        .is_some_and(str::is_empty)
    {
        return Err(anyhow::anyhow!("paths.records_dir must not be empty"));
    }
    if config
        .pointer("/paths/controller_authorization_nonce_file")
        .and_then(serde_json::Value::as_str)
        .is_some_and(str::is_empty)
    {
        return Err(anyhow::anyhow!(
            "paths.controller_authorization_nonce_file must not be empty"
        ));
    }
    if config
        .pointer("/paths/registration_credential_query_nonce_file")
        .and_then(serde_json::Value::as_str)
        .is_some_and(str::is_empty)
    {
        return Err(anyhow::anyhow!(
            "paths.registration_credential_query_nonce_file must not be empty"
        ));
    }
    Ok(())
}

