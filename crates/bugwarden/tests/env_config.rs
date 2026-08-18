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
//! - letting the environment override the command line.

use bugwarden::config::Cli;
use clap::error::ErrorKind;
use clap::Parser as _;

const VARS: [&str; 3] = [
    "MCP_ALLOWED_HOSTS",
    "BUGZILLA_USE_AUTH_HEADER",
    "MCP_READ_ONLY",
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

    // One variable carries the whole allowed-hosts list, comma- and/or
    // whitespace-separated, trimmed.
    std::env::set_var("MCP_ALLOWED_HOSTS", "a.example:8000, b.example");
    let cli = parse(&[]).expect("a host list parses");
    assert_eq!(
        cli.resolved_allowed_hosts(),
        ["a.example:8000", "b.example"],
        "MCP_ALLOWED_HOSTS must reach --allowed-hosts as separate entries"
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

    clear();
}
