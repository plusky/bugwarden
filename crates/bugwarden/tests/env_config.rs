//! Configuration read from the REAL process environment.
//!
//! ONE test on purpose: it mutates the process environment, which is only
//! safe while no other thread reads it, and libtest runs a binary's tests in
//! parallel. Put new environment cases inside this test rather than beside
//! it, and keep this file free of anything else.
//!
//! Coverage contract (each of these mutations must fail this test):
//! - dropping `env = "MCP_ALLOWED_HOSTS"` or `env = "BUGZILLA_USE_AUTH_HEADER"`;
//! - keeping the empty entry `MCP_ALLOWED_HOSTS=` produces, which would turn
//!   Host validation ON with nothing matchable and refuse every request;
//! - not splitting `MCP_ALLOWED_HOSTS=a b.example` on whitespace (a space is part of the authority);
//! - letting the environment override the command line;
//! - reading an OTLP variable from anywhere but the process environment, or
//!   letting an emptied `OTEL_EXPORTER_OTLP_ENDPOINT` leave export on;
//! - dropping `env = "BUGWARDEN_AUDIT_CONFIG"`, widening the exact-bytes
//!   `none` sentinel, or letting mere absence of the variable select
//!   OTLP-only auditing (the file may only be disabled explicitly).

use std::path::Path;

use bugwarden::audit::{select_sinks, SinkSelection};
use bugwarden::config::Cli;
use bugwarden::otel::{self, OtelEnv};
use clap::error::ErrorKind;
use clap::Parser as _;

const VARS: [&str; 11] = [
    "MCP_ALLOWED_HOSTS",
    "BUGZILLA_USE_AUTH_HEADER",
    "MCP_READ_ONLY",
    "BUGWARDEN_AUDIT_CONFIG",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_SERVICE_NAME",
    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
    "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
    "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
];

fn clear() {
    for var in VARS {
        std::env::remove_var(var);
    }
}

/// Parse a minimal command line, so only the variable under test decides.
fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
    let mut argv = vec![
        "bugwarden",
        "--bugzilla-server",
        "https://bugzilla.example.com",
    ];
    argv.extend_from_slice(args);
    Cli::try_parse_from(argv)
}

/// What `var=value` alone makes `read` see: the parsed flag, or the usage
/// error clap refused the value with.
fn outcome(var: &str, value: &str, read: fn(&Cli) -> bool) -> Result<bool, ErrorKind> {
    clear();
    std::env::set_var(var, value);
    let outcome = parse(&[]).map(|cli| read(&cli)).map_err(|e| e.kind());
    clear();
    outcome
}

#[test]
fn every_flag_is_settable_from_the_environment() {
    clear();

    // One variable carries the whole allowed-hosts list, comma-separated,
    // with whitespace around commas trimmed.
    std::env::set_var("MCP_ALLOWED_HOSTS", "a.example:8000, b.example");
    let cli = parse(&[]).expect("a host list parses");
    assert_eq!(
        cli.resolved_allowed_hosts(),
        ["a.example:8000", "b.example"],
        "MCP_ALLOWED_HOSTS must reach --allowed-hosts as separate entries"
    );

    // A missing-comma typo stays one entry and is refused. Splitting on
    // whitespace would manufacture `a` and `b.example`.
    std::env::set_var("MCP_ALLOWED_HOSTS", "a b.example");
    let cli = parse(&[]).expect("a space-containing value parses");
    assert_eq!(
        cli.resolved_allowed_hosts(),
        ["a b.example"],
        "MCP_ALLOWED_HOSTS must not split a single entry on whitespace"
    );
    assert!(
        cli.checked_allowed_hosts().is_err(),
        "a space-containing typo is a startup error, not two authorities"
    );

    // `MCP_ALLOWED_HOSTS=` is the set-but-empty "unset" idiom of unit files
    // and container specs (as for BUGZILLA_API_KEY_FILE): it names no host,
    // so Host validation stays off. Keeping the empty entry would instead
    // switch validation on with nothing rmcp can match, refusing every Host.
    std::env::set_var("MCP_ALLOWED_HOSTS", "");
    let cli = parse(&[]).expect("an empty value parses");
    assert!(
        cli.resolved_allowed_hosts().is_empty(),
        "MCP_ALLOWED_HOSTS= must read as unset, leaving Host validation off"
    );
    assert!(
        cli.checked_allowed_hosts()
            .expect("empty is unset, not an error")
            .is_none(),
        "MCP_ALLOWED_HOSTS= must leave Host validation off"
    );

    // Precedence: the command line wins over the environment (I9 is not at
    // stake either way — naming hosts only ever narrows what is served).
    std::env::set_var("MCP_ALLOWED_HOSTS", "env.example");
    let cli = parse(&["--allowed-hosts", "cli.example"]).expect("the flag parses");
    assert_eq!(
        cli.resolved_allowed_hosts(),
        ["cli.example"],
        "--allowed-hosts must win over MCP_ALLOWED_HOSTS"
    );

    // BUGZILLA_USE_AUTH_HEADER is read, and read exactly as MCP_READ_ONLY is:
    // clap's bool flags take the literal `true` or `false` from an
    // environment variable and make everything else a usage error.
    assert_eq!(
        outcome("BUGZILLA_USE_AUTH_HEADER", "true", |cli| cli
            .use_auth_header),
        Ok(true),
        "BUGZILLA_USE_AUTH_HEADER=true must select the Authorization header"
    );
    assert_eq!(
        outcome("BUGZILLA_USE_AUTH_HEADER", "false", |cli| cli
            .use_auth_header),
        Ok(false)
    );
    for value in [
        "true", "false", "TRUE", "True", "1", "0", "yes", "no", "on", "off", "",
    ] {
        assert_eq!(
            outcome("BUGZILLA_USE_AUTH_HEADER", value, |cli| cli.use_auth_header),
            outcome("MCP_READ_ONLY", value, |cli| cli.read_only),
            "BUGZILLA_USE_AUTH_HEADER={value:?} must be read exactly like MCP_READ_ONLY"
        );
    }

    // The OTLP export knobs are read by `bugwarden::otel`, never by clap,
    // so nothing above would notice if `OtelEnv::from_env` stopped reading
    // one. They live in this test because it owns process-environment
    // mutation for the whole crate.
    clear();
    assert!(
        otel::resolve(&OtelEnv::from_env())
            .expect("an environment with no endpoint resolves")
            .is_none(),
        "with no OTEL_EXPORTER_OTLP_ENDPOINT the export must be off"
    );

    std::env::set_var(
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "http://collector.example:4318",
    );
    std::env::set_var("OTEL_SERVICE_NAME", "bugwarden-edge");
    let cfg = otel::resolve(&OtelEnv::from_env())
        .expect("an endpoint resolves")
        .expect("an endpoint means export is on");
    assert_eq!(
        cfg.service_name(),
        "bugwarden-edge",
        "OTEL_SERVICE_NAME must reach the exported resource"
    );

    // The set-but-empty "unset" idiom again, and here it is the off switch
    // for the whole feature.
    std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "");
    assert!(
        otel::resolve(&OtelEnv::from_env())
            .expect("an emptied endpoint resolves")
            .is_none(),
        "OTEL_EXPORTER_OTLP_ENDPOINT= must read as unset, leaving export off"
    );

    // A protocol this build cannot speak is a startup error — but only
    // once an endpoint makes the transport matter.
    std::env::set_var("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc");
    assert!(
        otel::resolve(&OtelEnv::from_env())
            .expect("no endpoint decides everything")
            .is_none(),
        "with export off the protocol is not consulted"
    );
    std::env::set_var(
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "http://collector.example:4318",
    );
    let err = otel::resolve(&OtelEnv::from_env())
        .err()
        .expect("grpc must be refused");
    assert!(
        format!("{err}").contains("OTEL_EXPORTER_OTLP_PROTOCOL"),
        "the refusal must name the variable: {err}"
    );

    // Sink selection (issue #31, revised 2026-08-18). The variable reaches
    // the selection, and the literal `none` — exact bytes — is the ONLY
    // spelling that disables the audit file; absence beside an OTLP
    // endpoint refuses startup rather than silently going fileless.
    clear();
    std::env::set_var("BUGWARDEN_AUDIT_CONFIG", "/etc/bugwarden/audit.toml");
    let cli = parse(&[]).expect("a config path parses");
    assert_eq!(
        select_sinks(cli.audit_config.as_deref(), false).expect("file only"),
        SinkSelection::FileOnly,
        "BUGWARDEN_AUDIT_CONFIG must reach the sink selection"
    );
    assert_eq!(
        select_sinks(cli.audit_config.as_deref(), true).expect("both sinks"),
        SinkSelection::Both
    );
    std::env::set_var("BUGWARDEN_AUDIT_CONFIG", "none");
    let cli = parse(&[]).expect("the sentinel parses");
    assert_eq!(
        select_sinks(cli.audit_config.as_deref(), true).expect("otlp only"),
        SinkSelection::OtlpOnly,
        "BUGWARDEN_AUDIT_CONFIG=none must select the fileless sink"
    );
    assert!(
        select_sinks(cli.audit_config.as_deref(), false).is_err(),
        "`none` with no OTLP endpoint must refuse startup, never run sinkless"
    );
    // The command line wins over the environment, as everywhere.
    let cli = parse(&["--audit-config", "/from/cli.toml"]).expect("the flag parses");
    assert_eq!(
        cli.audit_config.as_deref(),
        Some(Path::new("/from/cli.toml"))
    );
    // Absence is not `none`: with an endpoint configured the server
    // demands an explicit file decision, and with none it audits nothing.
    clear();
    let cli = parse(&[]).expect("no variable parses");
    assert!(
        select_sinks(cli.audit_config.as_deref(), true).is_err(),
        "an OTLP endpoint without a file decision must refuse startup"
    );
    assert_eq!(
        select_sinks(cli.audit_config.as_deref(), false).expect("no audit"),
        SinkSelection::NoAudit
    );

    // The logs-specific endpoint alone turns export on, and is used as
    // given: a fleet that names only this variable expects logs exported,
    // and reading only the general one would leave it silently off.
    clear();
    std::env::set_var(
        "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
        "http://collector.example:4318/otlp/v1/logs",
    );
    let cfg = otel::resolve(&OtelEnv::from_env())
        .expect("a logs endpoint resolves")
        .expect("a logs endpoint alone means export is on");
    assert_eq!(cfg.service_name(), "bugwarden");

    clear();
}
