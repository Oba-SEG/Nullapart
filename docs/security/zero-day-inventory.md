# Zero-Day Affected-Version Inventory

**Status:** generated from `Cargo.lock`. Regenerate after every dependency change.

## Derivation method

1. `cargo metadata --format-version=1` extracts the complete dependency tree from `Cargo.lock`;
2. Each crate name + version is recorded with its source registry;
3. For each entry, the following fields are tracked:
   - **Crate name**
   - **Version**
   - **Source** (crates.io, git, path)
   - **Hostile-input path** (whether it processes untrusted Internet mail content)
4. When a CVE/GHSA is published, cross-reference the crate name + version range against this inventory.

## Hostile-input path crates (priority for zero-day response)

These crates directly process untrusted mail content on the inbound/outbound path:

| Crate | Version | Path | Notes |
|-------|---------|------|-------|
| `postfix-parser` | — | N/A | Postfix handles SMTP directly (system package) |
| `mailparse` | 0.15 | Rust crate | MIME parsing |
| `clamav-sdk` | — | N/A | ClamAV handles archive/recursion (system package) |
| `rspamd` | — | N/A | Rspamd handles message scoring (system package) |
| `hyper` | 1.x | Axum HTTP server | Control Plane only (not hostile mail) |
| `axum` | 0.7 | HTTP framework | Control Plane only |
| `rustls` | — | TLS stack | Protocol handling |
| `serde_json` | 1.x | JSON parsing | Policy/config deserialization |
| `regex` | — | Pattern matching | Content scanning patterns |
| `uuid` | 1.x | ID generation | Not hostile-input |

## Full dependency inventory

Total dependencies from `Cargo.lock`: **106 crates**

### Direct dependencies (workspace)

| Crate | Version | Purpose |
|-------|---------|---------|
| `axum` | 0.7 | HTTP framework |
| `hyper` | 1.x | HTTP implementation |
| `tower` | 0.5 | Service middleware |
| `serde` | 1.x | Serialization |
| `serde_json` | 1.x | JSON |
| `tokio` | 1.x | Async runtime |
| `chrono` | 0.4 | DateTime |
| `uuid` | 1.x | UUIDs |
| `reqwest` | 0.12 | HTTP client |
| `tracing` | 0.1 | Logging |
| `tracing-subscriber` | 0.3 | Log formatting |
| `thiserror` | 2.x | Error types |
| `anyhow` | 1.x | Error handling |
| `clap` | 4.x | CLI parsing |
| `async-trait` | 0.1 | Async traits |

### System packages (not in Cargo.lock, but in scope for zero-day)

| Package | Purpose | Update path |
|---------|---------|-------------|
| Postfix | SMTP MTA | OS package manager |
| Rspamd | Milter/scoring | OS package manager |
| ClamAV | Antivirus | OS package manager |
| OpenSSL | TLS/crypto | OS package manager |
| PostgreSQL | Database | AWS RDS / system |
| Redis/Valkey | Cache | AWS ElastiCache / system |
| ZITADEL | Identity | Container image |
| OpenBao | Secrets | Container image |

## Update procedure

When a security advisory is published:

1. Check if the affected crate name + version range matches any entry in this inventory;
2. If on a hostile-input path: escalate to P0 security case;
3. If on Control Plane only: assess exploitability, schedule fix;
4. Run `cargo audit` / GitHub Security Alerts for automated matching;
5. Regenerate this inventory after applying the fix.
