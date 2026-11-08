// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct RuntimeConfig {
    pub tokio: oan_config::TokioConfig,
    pub did_verification: oan_crypto::VerificationExecutorOptions,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            tokio: oan_config::TokioConfig {
                thread_stack_size_mib: Some(8),
                ..Default::default()
            },
            did_verification: Default::default(),
        }
    }
}

impl RuntimeConfig {
    pub fn validate(&mut self) -> Result<()> {
        // Partial [runtime.tokio] sections retain this node's original stack default.
        self.tokio.thread_stack_size_mib.get_or_insert(8);
        self.tokio.validate()?;
        self.did_verification.validate().map_err(|e| anyhow!(e))
    }

    pub fn build(&self) -> Result<tokio::runtime::Runtime> {
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.enable_all();
        if let Some(v) = self.tokio.worker_threads {
            builder.worker_threads(v);
        }
        if let Some(v) = self.tokio.stack_bytes()? {
            builder.thread_stack_size(v);
        }
        if let Some(v) = self.tokio.max_blocking_threads {
            builder.max_blocking_threads(v);
        }
        Ok(builder.build()?)
    }
}

pub(super) fn pool_options(
    config: &oan_config::PoolConfig,
    url: &str,
) -> Result<oan_storage::PoolOptions> {
    let mut resolved = config.clone();
    resolved.resolve(Some(url))?;
    Ok(oan_storage::PoolOptions {
        max_connections: resolved
            .max_connections
            .ok_or_else(|| anyhow!("unresolved database pool"))?,
        acquire_timeout_seconds: resolved
            .acquire_timeout_seconds
            .ok_or_else(|| anyhow!("unresolved database timeout"))?,
        idle_timeout_seconds: resolved.idle_timeout_seconds,
        max_lifetime_seconds: resolved.max_lifetime_seconds,
    })
}
