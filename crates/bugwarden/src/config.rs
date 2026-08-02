//! CLI configuration for bugwarden.
//!
//! Precedence: CLI argument > environment variable > hardcoded default.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use clap::builder::TypedValueParser as _;
use clap::{Parser, ValueEnum};

/// Transport for the MCP server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Transport {
    /// Streamable HTTP transport (default). Clients send the Bugzilla API key
    /// per-request via the API key header, unless `--api-key-file` selects
    /// server-held key mode (then the header is not consulted at all).
    Http,
    /// Stdio transport. The API key comes from `--api-key` /
    /// `BUGZILLA_API_KEY` or `--api-key-file` at startup.
    Stdio,
}

/// MCP server for Bugzilla interaction, with operator-controlled security
/// guards.
///
/// `Debug` is implemented by hand to redact `api_key`: the struct holds the
/// startup key, and key material must never reach logs or error text (I12).
#[derive(Parser)]
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
    /// 'ApiKey' or the MCP_API_KEY_HEADER environment variable. Not consulted
    /// in server-held key mode (--api-key-file over http).
    #[arg(long, env = "MCP_API_KEY_HEADER", default_value = "ApiKey")]
    pub api_key_header: String,

    /// Bugzilla API key. Required for --transport stdio (no HTTP headers
    /// exist there) unless --api-key-file provides it. Environment variable
    /// BUGZILLA_API_KEY can also be used. Ignored for --transport http
    /// (clients send the key per-request via the API key header; use
    /// --api-key-file for a server-held key).
    #[arg(long, env = "BUGZILLA_API_KEY", hide_env_values = true)]
    pub api_key: Option<String>,

    /// Path to a file holding the Bugzilla API key (e.g. a container secret or
    /// systemd LoadCredential path). Mutually exclusive with --api-key. Over
    /// http this selects server-held key mode: every request is served with
    /// this key and the per-request API key header is not consulted. An empty
    /// value counts as absent, like --api-key (so `BUGZILLA_API_KEY_FILE=` is
    /// an unset, not an error).
    #[arg(
        long,
        env = "BUGZILLA_API_KEY_FILE",
        value_parser = clap::builder::OsStringValueParser::new().map(PathBuf::from)
    )]
    pub api_key_file: Option<PathBuf>,

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

    /// Path to the audit configuration TOML file (see examples/audit.toml).
    /// Environment variable BUGWARDEN_AUDIT_CONFIG can also be used.
    /// Without it no audit stream is written.
    #[arg(long, env = "BUGWARDEN_AUDIT_CONFIG")]
    pub audit_config: Option<PathBuf>,
}

/// Manual impl so the startup key can never reach a log or error through a
/// `{:?}` of the config (I12); every other field prints as derived.
impl std::fmt::Debug for Cli {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cli")
            .field("bugzilla_server", &self.bugzilla_server)
            .field("transport", &self.transport)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("api_key_header", &self.api_key_header)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("api_key_file", &self.api_key_file)
            .field("use_auth_header", &self.use_auth_header)
            .field("read_only", &self.read_only)
            .field("policy", &self.policy)
            .field("audit_config", &self.audit_config)
            .finish()
    }
}

/// Who holds the Bugzilla API key, resolved exactly once at startup.
///
/// No Debug impl on purpose: the `Server` variant carries the key itself,
/// and key material must never reach logs or error text (I12).
#[derive(Clone)]
pub enum KeyCustody {
    /// The server owns one key resolved at startup (stdio startup key, or
    /// http server-held mode). Requests never consult the key header.
    Server(String),
    /// http per-request mode: each request must carry the key header.
    PerRequest,
}

impl Cli {
    /// Resolve who holds the Bugzilla API key — the whole table, once, at
    /// startup.
    ///
    /// - `--api-key` and `--api-key-file` together: error (mutually
    ///   exclusive; there is no fallback between them).
    /// - `--api-key-file` (any transport): the file's trimmed content is the
    ///   server-held key; over http the per-request header is not consulted.
    /// - stdio with `--api-key`: the startup key. Without either source,
    ///   stdio errors here — at startup, never at first request.
    /// - http with `--api-key` alone: warn and ignore, stay per-request.
    ///   Deliberately NOT upgraded to server-held: `BUGZILLA_API_KEY` is a
    ///   generic env name other Bugzilla tooling sets, and flipping it to
    ///   server-held would silently change deployed custody semantics.
    ///
    /// Errors name the key file's path, never its contents (I12). The log
    /// line emitted here states mode and source only — no key material.
    pub fn resolve_key_custody(&self) -> anyhow::Result<KeyCustody> {
        // An empty --api-key counts as absent, as everywhere else; an empty
        // --api-key-file path likewise (`BUGZILLA_API_KEY_FILE=` is the
        // set-but-empty "unset" idiom of systemd units and container specs).
        let startup_key = self.api_key.as_deref().filter(|k| !k.is_empty());
        let key_file = self
            .api_key_file
            .as_deref()
            .filter(|p| !p.as_os_str().is_empty());
        if startup_key.is_some() && key_file.is_some() {
            anyhow::bail!(
                "--api-key (BUGZILLA_API_KEY) and --api-key-file (BUGZILLA_API_KEY_FILE) \
                 are mutually exclusive; pass exactly one"
            );
        }
        if let Some(path) = key_file {
            let key = read_key_file(path)?;
            match self.transport {
                Transport::Stdio => tracing::info!("API key: startup key (stdio)"),
                Transport::Http => tracing::info!(
                    "API key: server-held (from {}); the per-request '{}' header \
                     is not consulted",
                    path.display(),
                    self.api_key_header
                ),
            }
            return Ok(KeyCustody::Server(key));
        }
        match self.transport {
            Transport::Stdio => match startup_key {
                Some(key) => {
                    tracing::info!("API key: startup key (stdio)");
                    Ok(KeyCustody::Server(key.to_owned()))
                }
                None => anyhow::bail!(
                    "--transport stdio requires --api-key or the BUGZILLA_API_KEY environment variable"
                ),
            },
            Transport::Http => {
                if self.api_key.is_some() {
                    tracing::warn!(
                        "--api-key / BUGZILLA_API_KEY is set but ignored with --transport http \
                         (clients send the key per-request via the API key header; use \
                         --api-key-file for a server-held key). Unset it to clean the config."
                    );
                }
                tracing::info!(
                    "API key: per-request via the '{}' header",
                    self.api_key_header
                );
                Ok(KeyCustody::PerRequest)
            }
        }
    }
}

/// Read and trim the API key file. Errors name the path only, never the
/// file's contents (I12). On unix, warns when the file is readable by group
/// or others: the key is a credential and should be 0600.
fn read_key_file(path: &Path) -> anyhow::Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                tracing::warn!(
                    path = %path.display(),
                    mode = format!("{:o}", mode & 0o777),
                    "API key file is accessible by group or others; \
                     restrict it to 0600"
                );
            }
        }
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read the API key file {}", path.display()))?;
    let key = raw.trim();
    if key.is_empty() {
        anyhow::bail!("the API key file {} is empty", path.display());
    }
    Ok(key.to_owned())
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use clap::Parser as _;

    use super::*;

    /// A `Cli` for `transport` with both key sources explicitly cleared, so
    /// the ambient environment (`BUGZILLA_API_KEY`, `BUGZILLA_API_KEY_FILE`)
    /// cannot leak into what a test resolves.
    fn base_cli(transport: &str) -> Cli {
        let mut cli = Cli::parse_from([
            "bugwarden",
            "--bugzilla-server",
            "https://bugzilla.example.com",
            "--transport",
            transport,
        ]);
        cli.api_key = None;
        cli.api_key_file = None;
        cli
    }

    fn key_file(content: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("temp key file");
        file.write_all(content.as_bytes()).expect("write key file");
        file
    }

    fn server_key(custody: KeyCustody) -> String {
        match custody {
            KeyCustody::Server(key) => key,
            KeyCustody::PerRequest => panic!("expected the server-held key"),
        }
    }

    /// The resolution error, by match: `expect_err` needs the Ok type to be
    /// Debug, which `KeyCustody` deliberately is not (it carries the key).
    fn resolve_err(cli: &Cli) -> anyhow::Error {
        match cli.resolve_key_custody() {
            Err(e) => e,
            Ok(_) => panic!("key custody resolution must fail"),
        }
    }

    #[test]
    fn both_key_sources_are_a_startup_error_naming_both_flags() {
        for transport in ["stdio", "http"] {
            let file = key_file("file-key\n");
            let mut cli = base_cli(transport);
            cli.api_key = Some("flag-key".into());
            cli.api_key_file = Some(file.path().to_path_buf());
            let msg = format!("{:#}", resolve_err(&cli));
            // "--api-key" is a substring of "--api-key-file", so pin each
            // flag together with its env var — unambiguous per flag.
            assert!(
                msg.contains("--api-key (BUGZILLA_API_KEY)"),
                "unexpected error: {msg}"
            );
            assert!(
                msg.contains("--api-key-file (BUGZILLA_API_KEY_FILE)"),
                "unexpected error: {msg}"
            );
        }
    }

    #[test]
    fn stdio_without_any_key_source_fails_at_resolution() {
        let cli = base_cli("stdio");
        let msg = format!("{:#}", resolve_err(&cli));
        assert!(msg.contains("--transport stdio requires"), "{msg}");

        // An empty --api-key counts as absent.
        let mut cli = base_cli("stdio");
        cli.api_key = Some(String::new());
        assert!(cli.resolve_key_custody().is_err());
    }

    #[test]
    fn empty_or_whitespace_key_file_is_an_error_naming_the_path() {
        for content in ["", " \n\t \n"] {
            let file = key_file(content);
            let mut cli = base_cli("http");
            cli.api_key_file = Some(file.path().to_path_buf());
            let msg = format!("{:#}", resolve_err(&cli));
            assert!(
                msg.contains(&file.path().display().to_string()),
                "the error must name the path: {msg}"
            );
        }
    }

    #[test]
    fn key_file_content_is_trimmed() {
        let file = key_file("the-key\n");
        let mut cli = base_cli("http");
        cli.api_key_file = Some(file.path().to_path_buf());
        let custody = cli.resolve_key_custody().expect("key file resolves");
        assert_eq!(server_key(custody), "the-key");
    }

    #[test]
    fn unreadable_key_file_is_an_error_naming_the_path() {
        let mut cli = base_cli("http");
        cli.api_key_file = Some(PathBuf::from("/nonexistent/bugwarden-key"));
        let msg = format!("{:#}", resolve_err(&cli));
        assert!(msg.contains("/nonexistent/bugwarden-key"), "{msg}");
    }

    #[test]
    fn stdio_takes_the_key_from_the_file_too() {
        let file = key_file("stdio-file-key\n");
        let mut cli = base_cli("stdio");
        cli.api_key_file = Some(file.path().to_path_buf());
        let custody = cli.resolve_key_custody().expect("key file resolves");
        assert_eq!(server_key(custody), "stdio-file-key");
    }

    #[test]
    fn http_with_startup_key_alone_stays_per_request() {
        // Warn-and-ignore, pinned: --api-key over http must NOT silently
        // upgrade to server-held custody.
        let mut cli = base_cli("http");
        cli.api_key = Some("flag-key".into());
        let custody = cli.resolve_key_custody().expect("http resolves");
        assert!(
            matches!(custody, KeyCustody::PerRequest),
            "http + --api-key must stay per-request"
        );
    }

    #[test]
    fn stdio_startup_key_is_server_custody() {
        let mut cli = base_cli("stdio");
        cli.api_key = Some("startup-key".into());
        let custody = cli.resolve_key_custody().expect("stdio resolves");
        assert_eq!(server_key(custody), "startup-key");
    }

    #[test]
    fn empty_api_key_file_counts_as_absent() {
        // `BUGZILLA_API_KEY_FILE=` (set but empty, the systemd/container
        // "unset" idiom) must behave exactly like an unset variable: the
        // parser accepts the empty value and resolution ignores it —
        // mirroring the empty --api-key convention.
        let mut cli = Cli::parse_from([
            "bugwarden",
            "--bugzilla-server",
            "https://bugzilla.example.com",
            "--transport",
            "http",
            "--api-key-file",
            "",
        ]);
        cli.api_key = None;
        let custody = cli.resolve_key_custody().expect("http resolves");
        assert!(
            matches!(custody, KeyCustody::PerRequest),
            "an empty key file path must not select server-held mode"
        );

        // On stdio the empty path falls through to the no-key-source error,
        // not to a read of the path "".
        let mut cli = base_cli("stdio");
        cli.api_key_file = Some(PathBuf::new());
        let msg = format!("{:#}", resolve_err(&cli));
        assert!(msg.contains("--transport stdio requires"), "{msg}");
    }

    #[test]
    fn cli_debug_never_prints_the_startup_key_i12() {
        let mut cli = base_cli("stdio");
        cli.api_key = Some("SUPERSECRETKEY123".into());
        let printed = format!("{cli:?}");
        assert!(
            !printed.contains("SUPERSECRETKEY123"),
            "Debug must redact the key: {printed}"
        );
        assert!(printed.contains("<redacted>"), "{printed}");
    }

    #[test]
    fn startup_log_states_mode_and_source_never_key_material_i12() {
        // Acceptance criterion: the resolved custody is visible in the
        // startup log. Server-held: the line names the mode and the path —
        // and never the key. Per-request: the line names the header.
        let file = key_file("hush-key\n");
        let mut cli = base_cli("http");
        cli.api_key_file = Some(file.path().to_path_buf());
        let (custody, logs) = crate::testlog::capture_logs(|| cli.resolve_key_custody());
        drop(custody.expect("key file resolves"));
        assert!(logs.contains("server-held"), "startup log: {logs}");
        assert!(
            logs.contains(&file.path().display().to_string()),
            "the log must name the source path: {logs}"
        );
        assert!(
            !logs.contains("hush-key"),
            "the log must never carry key material (I12): {logs}"
        );

        let cli = base_cli("http");
        let (custody, logs) = crate::testlog::capture_logs(|| cli.resolve_key_custody());
        drop(custody.expect("http resolves"));
        assert!(
            logs.contains("per-request via the 'ApiKey' header"),
            "startup log: {logs}"
        );
    }
}
