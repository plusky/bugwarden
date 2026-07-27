//! CLI configuration for bugwarden.
//!
//! Precedence: CLI argument > environment variable > hardcoded default.

use std::path::PathBuf;

use clap::{Parser, ValueEnum};

/// Transport for the MCP server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Transport {
    /// Streamable HTTP transport (default). Clients send the Bugzilla API key
    /// per-request via the API key header.
    Http,
    /// Stdio transport. The API key comes from `--api-key` /
    /// `BUGZILLA_API_KEY` at startup.
    Stdio,
}

/// MCP server for Bugzilla interaction, with operator-controlled security
/// guards.
#[derive(Debug, Parser)]
#[command(name = "bugwarden", version, about)]
pub struct Cli {
    /// Base URL of the Bugzilla server (e.g., 'https://bugzilla.example.com').
    /// Environment variable BUGZILLA_SERVER is used if the argument is not
    /// provided.
    #[arg(long, env = "BUGZILLA_SERVER")]
    pub bugzilla_server: String,

    /// Transport for the MCP server: 'http' (default) or 'stdio'. Environment
    /// variable MCP_TRANSPORT can also be used.
    #[arg(long, env = "MCP_TRANSPORT", value_enum, default_value = "http")]
    pub transport: Transport,

    /// Host address for the MCP server to listen on (http transport only).
    /// Defaults to 127.0.0.1 or the MCP_HOST environment variable.
    #[arg(long, env = "MCP_HOST", default_value = "127.0.0.1")]
    pub host: String,

    /// Port for the MCP server to listen on (http transport only). Defaults
    /// to 8000 or the MCP_PORT environment variable.
    #[arg(long, env = "MCP_PORT", default_value_t = 8000)]
    pub port: u16,

    /// HTTP header for clients to send the Bugzilla API key. Defaults to
    /// 'ApiKey' or the MCP_API_KEY_HEADER environment variable.
    #[arg(long, env = "MCP_API_KEY_HEADER", default_value = "ApiKey")]
    pub api_key_header: String,

    /// Bugzilla API key. Required for --transport stdio (no HTTP headers
    /// exist there). Environment variable BUGZILLA_API_KEY can also be used.
    /// Ignored for --transport http (clients send the key per-request via the
    /// API key header).
    #[arg(long, env = "BUGZILLA_API_KEY", hide_env_values = true)]
    pub api_key: Option<String>,

    /// Use 'Authorization: Bearer' header instead of the api_key query
    /// parameter (required for some Bugzilla instances).
    #[arg(long)]
    pub use_auth_header: bool,

    /// Disables all tools which modify the state of a bug. Environment
    /// variable MCP_READ_ONLY=true can also be used. Can only tighten the
    /// guard policy, never loosen it.
    #[arg(long, env = "MCP_READ_ONLY")]
    pub read_only: bool,

    /// Path to the guard policy TOML file. Environment variable
    /// BUGWARDEN_POLICY can also be used. Without it an allow-all default
    /// policy is used.
    #[arg(long, env = "BUGWARDEN_POLICY")]
    pub policy: Option<PathBuf>,
}
