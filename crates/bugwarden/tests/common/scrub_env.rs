//! The ambient environment a spawned `bugwarden` must not inherit, and the
//! walker that holds the list to every variable the binary reads (#237).
//!
//! Included by `#[path]` from each user rather than declared in
//! `common/mod.rs`: that module compiles into every test binary that says
//! `mod common;`, so a helper only some of them use would be `dead_code` in
//! the rest, which `-D warnings` rejects (#167, #214, #222, #229).
//!
//! Not the merge `common/pinned_cli.rs` rules out. That one refuses to scrub
//! the *real* environment in-process, because libtest runs a binary's tests
//! on parallel threads; sharing a `const` scrubs nothing.

/// The two HTTP bearer tokens, read by `bugwarden::http_auth` and not by
/// clap — no `get_env` sweep can reach them, hence the by-name arm of the
/// walker below. Named as a set so a stdio-only spawn can say which two it
/// drops instead of writing a third list.
pub const HTTP_TOKEN_VARS: &[&str] = &[
    bugwarden::http_auth::WRITE_TOKEN_VAR,
    bugwarden::http_auth::READ_TOKEN_VAR,
];

/// Every environment variable the binary reads, cleared before each spawn:
/// an ambient value would change exactly what is under test. The spawned leg
/// only; `pinned_cli` covers the in-process one.
///
/// Scrubbed as one set rather than per test — a knob inert for one
/// transport is still a knob, and pruning is how the list falls behind
/// `Cli`. The two bearer tokens are spelled out rather than taken from
/// [`HTTP_TOKEN_VARS`], which would make the walker's by-name check
/// tautological.
pub const AMBIENT_VARS: &[&str] = &[
    "BUGZILLA_SERVER",
    "BUGZILLA_API_KEY",
    "BUGZILLA_API_KEY_FILE",
    "BUGWARDEN_POLICY",
    "BUGWARDEN_AUDIT_CONFIG",
    "BUGWARDEN_HTTP_TOKEN",
    "BUGWARDEN_HTTP_READ_TOKEN",
    "BUGZILLA_USE_AUTH_HEADER",
    "MCP_TRANSPORT",
    "MCP_HOST",
    "MCP_PORT",
    "MCP_ALLOWED_HOSTS",
    "MCP_READ_ONLY",
    "MCP_API_KEY_HEADER",
    "RUST_LOG",
    // Read by the otel module, not by `Cli`: a developer exporting to a
    // collector would otherwise have every spawned child export too, and
    // an unreachable one would slow the tests down for no reason.
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_SERVICE_NAME",
    // The signal-specific trio, which the OTLP spec makes override the
    // three above — so leaving them ambient would override the test's own
    // world, not merely add to it.
    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
    "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
    "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
];

/// Assert `scrubbed` covers every environment variable a spawned binary
/// reads, so a flag or a variable added later cannot quietly go on reaching
/// the child from the runner's environment and changing what is measured.
///
/// Three populations, because no single sweep sees them all: clap's `env`
/// fallbacks, [`bugwarden::otel::ENV_VARS`] (read outside clap, so no `Arg`
/// carries them), and `by_name` — variables nothing enumerates at all.
/// Pass [`HTTP_TOKEN_VARS`] for `by_name`, or `&[]` from a caller whose
/// list omits them on purpose.
pub fn assert_the_scrub_list_covers_every_environment_fallback(
    scrubbed: &[&str],
    by_name: &[&str],
) {
    let mut cmd = bugwarden::config::command();
    cmd.build();
    let unscrubbed: Vec<String> = cmd
        .get_arguments()
        .filter_map(clap::Arg::get_env)
        .map(|env| env.to_string_lossy().into_owned())
        .filter(|env| !scrubbed.contains(&env.as_str()))
        .collect();
    assert!(
        !scrubbed.is_empty() && cmd.get_arguments().any(|arg| arg.get_env().is_some()),
        "the check is only evidence while both lists are non-empty"
    );
    assert!(
        unscrubbed.is_empty(),
        "these environment fallbacks reach the spawned binary: {unscrubbed:?}"
    );
    for var in by_name {
        assert!(scrubbed.contains(var), "{var} must be scrubbed");
    }
    let unscrubbed_otel: Vec<&str> = bugwarden::otel::ENV_VARS
        .iter()
        .copied()
        .filter(|var| !scrubbed.contains(var))
        .collect();
    assert!(
        unscrubbed_otel.is_empty(),
        "these OTLP variables reach the spawned binary: {unscrubbed_otel:?}"
    );
}
