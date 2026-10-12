//! Process-environment test for the OTLP exporter configuration.
//!
//! This file holds exactly ONE test that touches the process environment,
//! on purpose: `set_var`/`remove_var` race any concurrent reader in the
//! same process, and libtest runs one binary's tests on parallel threads,
//! so an env-mutating test cannot share a binary (see
//! `tests/common/pinned_cli.rs`, which bans the pattern, and
//! `env_config.rs`, the other single-purpose global-state binary).
//! Separate processes have separate environments, so isolation here is
//! complete. Do not add a second environment-touching test to this file.

use bugwarden::otel::{resolve, OtelEnv, ENDPOINT_VAR, ENV_VARS, PROTOCOL_VAR};

#[test]
fn emptied_protocol_reads_as_unset() {
    // The cleared-variable idiom reaches `from_env`, not just
    // `resolve`: an emptied protocol must read as absence there, or a
    // fleet-wide empty default refuses to start an exporting server.
    // This test owns the whole OTEL sweep for its duration — nothing
    // else in this binary reads the process environment — and restores
    // every variable afterwards.
    struct Restore(Vec<(&'static str, Option<String>)>);
    impl Drop for Restore {
        fn drop(&mut self) {
            for (var, value) in std::mem::take(&mut self.0) {
                if let Some(value) = value {
                    std::env::set_var(var, value);
                } else {
                    std::env::remove_var(var);
                }
            }
        }
    }
    let _restore = Restore(
        ENV_VARS
            .iter()
            .map(|var| (*var, std::env::var(var).ok()))
            .collect(),
    );
    for var in ENV_VARS {
        std::env::remove_var(var);
    }
    std::env::set_var(ENDPOINT_VAR, "http://c:4318");
    std::env::set_var(PROTOCOL_VAR, "");
    let env = OtelEnv::from_env();
    assert!(
        env.protocol.is_none(),
        "an emptied protocol must read as unset"
    );
    assert!(
        resolve(&env)
            .expect("an emptied protocol resolves")
            .is_some(),
        "an emptied protocol must leave export on"
    );
}
