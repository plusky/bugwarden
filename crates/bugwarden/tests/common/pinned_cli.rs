//! Parse a `Cli` with every clap `env` fallback dropped, so a harness's
//! configuration comes from its argv and clap's defaults alone (#190, #214).
//!
//! Included by `#[path]` from each user rather than declared in
//! `common/mod.rs`: that module is compiled into every test binary that
//! says `mod common;`, so a helper only some of them use would be
//! `dead_code` in the rest, which `-D warnings` rejects (#167). `#[path]`
//! is also what lets the crate's own unit tests share this file, and that
//! is why nothing here names the crate — `bugwarden::config::Cli` does not
//! resolve inside `bugwarden`, so the type arrives as a parameter. The
//! generic buys nothing else; [`MINIMAL_ARGV`] below is `Cli`'s.
//!
//! Not `std::env::remove_var`: libtest runs a binary's tests on parallel
//! threads, so mutating the process environment races every other test in
//! the binary (`tests/env_config.rs`).

/// A command line carrying only what `Cli` requires, for the probe below.
const MINIMAL_ARGV: &[&str] = &["bugwarden", "--bugzilla-server", "https://bugzilla.example"];

/// Drop every `env` fallback from `cmd`, so parsing it consults only argv.
///
/// `Arg::env` snapshots the variable when the command is built, so the
/// reset covers fields added to `Cli` after this line was written — which
/// is the point. `common/scrub_env.rs` solves the other half of the same
/// problem for every spawning binary, and the two stay separate: that list
/// scrubs the environment of a *spawned* child, and doing the same
/// in-process would race every other test in the binary.
fn pin_environment(cmd: clap::Command) -> clap::Command {
    cmd.mut_args(|arg| arg.env(None::<&'static str>))
}

/// Parse `argv` through `C`'s own clap command with the environment pinned
/// out, giving the clap defaults for everything argv omits.
///
/// Two drifts nothing here catches: a test calling `C::parse_from` instead
/// of this, and an env-backed arg on a future subcommand — `mut_args` and
/// `get_arguments` both walk top-level args only.
pub fn pinned<C: clap::CommandFactory + clap::FromArgMatches>(argv: &[&str]) -> C {
    let matches = pin_environment(C::command())
        .try_get_matches_from(argv)
        .expect("the harness command line must parse");
    C::from_arg_matches(&matches).expect("the harness command line must build a Cli")
}

/// The pin is worth its doc comment only if the command really keeps no
/// fallback, and only if the unpinned command still has some — a check over
/// an already-empty set can never fail.
pub fn assert_the_pin_drops_every_fallback<C: clap::CommandFactory>() {
    let mut pinned = pin_environment(C::command());
    pinned.build();
    let leaking: Vec<String> = pinned
        .get_arguments()
        .filter_map(clap::Arg::get_env)
        .map(|env| env.to_string_lossy().into_owned())
        .collect();
    assert!(
        leaking.is_empty(),
        "these environment fallbacks still reach the harness: {leaking:?}"
    );

    let mut real = C::command();
    real.build();
    assert!(
        real.get_arguments().any(|arg| arg.get_env().is_some()),
        "the binary declares no environment fallback at all, so the assertion \
         above proves nothing"
    );
}

/// The drift the pin exists to survive: a `Cli` field added later, with an
/// `env` fallback whose variable is set in the runner's environment. Any
/// variable this process already carries reproduces it, so the check never
/// mutates the environment libtest shares across threads.
pub fn assert_the_pin_neutralises_a_flag_added_later<C: clap::CommandFactory>() {
    let (name, value) = std::env::vars_os()
        .next()
        .expect("the test process must carry at least one environment variable");
    // clap only accepts a `'static` variable name without its `string`
    // feature; one leaked name per run is cheaper than turning that on.
    let name: &'static std::ffi::OsStr = Box::leak(name.into_boxed_os_str());
    let added_later = || {
        clap::Arg::new("added-later")
            .long("added-later")
            .env(name)
            .value_parser(clap::builder::OsStringValueParser::new())
    };

    // Added *after* the pin, so only the probe keeps a fallback: a
    // malformed ambient value for a real one (`MCP_PORT=notanumber`) would
    // otherwise fail this check.
    let ambient = pin_environment(C::command())
        .arg(added_later())
        .try_get_matches_from(MINIMAL_ARGV)
        .expect("the probe command line must parse");
    assert_eq!(
        ambient.get_one::<std::ffi::OsString>("added-later"),
        Some(&value),
        "the probe variable must reach an unpinned field, or this proves nothing"
    );

    let pinned = pin_environment(C::command().arg(added_later()))
        .try_get_matches_from(MINIMAL_ARGV)
        .expect("the probe command line must parse");
    assert_eq!(
        pinned.get_one::<std::ffi::OsString>("added-later"),
        None,
        "{name:?} reached a pinned field"
    );
}
