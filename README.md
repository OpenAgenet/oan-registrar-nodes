# OAN Registrar Node

Registrar service workspace for OpenAgenet (OAN), an open infrastructure project
for the Internet of Agents (IoA). A Registrar node is the admission-facing
service that accepts resource registration submissions, validates DID and
resource metadata, checks authorized-domain coverage, and forwards verified
packages to Root for publication and distribution.

This repository owns:

- `registrar-node`

Shared protocol, crypto, storage, and service-security crates live in the
sibling `oan-protocol-common` repository.

## Service Role

The Registrar node is where builders submit Agent Service, Skill, MCP Server,
and Tool/API resources. It supports governance-aware admission by combining its
own authorized-domain scope with DID-control checks and Root verification. It
also exposes metadata assistance used by the official website Register page and
community skill.

Key routes implemented by `services/registrar-node` include:

- `GET /health`
- `GET /registrar/did`
- `GET /registrar/status`
- `GET /registrar/stats`
- `GET /registrar/root-authorization`
- `POST /resources/register`
- `POST /resources/submit`
- `GET /resources`
- `GET /resources/{did}`
- `GET /capability-tree`
- `POST /capability-tags/suggest`
- `POST /capability-tags/normalize`
- `GET /registration/domain-catalog`

For public browser workflows, the official website gateway exposes the current
registration route at `https://www.openagenet.xyz/resources/register`.

## Local Checks

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace -j 1
```

Full-network integration tests, deployment gates, and benchmarks are maintained
separately by official operators. Lightweight developer scenarios live in
`oan-examples`. Service-node identity material should be provided by the
operator for each deployment; this repository does not own private node
identity material.

## License

This core service repository is licensed under `Apache-2.0`. Brand and
official-node identity rights are reserved separately.


## Typed configuration and offline checks

The service loads one UTF-8 TOML file. Precedence is code defaults, TOML,
legacy database-pool environment variables (where applicable), then `OAN_REGISTRAR__...`
scalar environment overrides. `--config` selects the file; it does not silently
create one when missing. Unknown fields, duplicate aliases, invalid types and
invalid runtime capacities are rejected. Configuration changes require restart.

```text
registrar-node --config services/registrar-node/config.example.toml check-config
registrar-node --config services/registrar-node/config.example.toml print-effective-config
```

These commands run without starting Tokio, opening a database, reading identity
material, connecting upstream, creating directories or writing runtime state.
The effective-config command prints redacted JSON plus per-field sources;
it is for inspection, not a round-trippable deployment file. URLs/endpoints and
tokens are hidden. Preserve the original protected configuration for deployment.

The old positional config path remains accepted. Relative paths remain based on
the configuration directory. `OAN_REGISTRAR__RUNTIME__DID_VERIFICATION__WORKER_COUNT=4`
is an example override, not the default. Omitted verification settings retain
6 workers, a bounded queue of 12, and 16 MiB worker stacks. Tokio retains an
8 MiB stack; omitted Tokio worker/blocking counts retain runtime defaults.

`[database.pool]` supports `max_connections` and `acquire_timeout_seconds`.
PostgreSQL additionally supports `idle_timeout_seconds` and
`max_lifetime_seconds`. Defaults remain PostgreSQL 8 / SQLite 32 connections,
30 seconds acquisition timeout, and PostgreSQL idle/lifetime 30/300 seconds.
Existing `OAN_POSTGRES_*` / `OAN_SQLITE_*` pool variables remain compatible;
module-prefixed overrides take precedence. The backend still comes exclusively
from `paths.database_url`; an absent/empty URL retains file storage.

Remove previously unused `[node]` sections before enabling strict checks.
Arrays remain TOML-only; environment list splitting is not supported.
No identities, credentials, business records, nonce state or indexes are migrated.

Remove unused `[security.submit]` and `security.upstream.protocol_label` fields. This change does not add admission limits or change upstream HTTP timeout policy.
