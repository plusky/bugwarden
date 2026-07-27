# Rust Workspace Guidelines

These instructions apply to this repository — a root Rust workspace with
sources under `crates/`. The binding design contract is `docs/DESIGN.md`;
when this file and DESIGN.md disagree, DESIGN.md wins.

## Workspace Commands

Run commands from the repository root:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets --locked
cargo deny check
```

Use the toolchain pinned in `rust-toolchain.toml` (repo root, currently
`1.97.0`). The workspace MSRV is declared once in `Cargo.toml`
(`rust-version = "1.85"`); do not introduce APIs or dependencies which
require a newer compiler without deliberately updating both the pin and the
MSRV policy. CI and reproducible local checks use the committed
`Cargo.lock`, so use `--locked` for verification.

## Workspace Architecture

- `bugwarden-core` is the portable domain layer: the guard policy engine
  (`policy`, `guard`) and the async Bugzilla REST client (`client`). It
  MUST NOT depend on `rmcp`, `axum`, `clap`, or any MCP/transport crate.
- `bugwarden` is the binary: clap CLI parsing, the rmcp MCP server, and the
  stdio / streamable-HTTP transports. It must not duplicate guard or client
  logic.
- Keep the dependency direction acyclic: `bugwarden -> bugwarden-core`,
  never the reverse.
- Both crates inherit `[workspace.package]` metadata and
  `[workspace.lints]` (`[lints] workspace = true` in each crate manifest).

## Security guard rules

The security guards are defined in `docs/DESIGN.md` as invariants
**I1–I13**. They are normative: reviewers verify them, and CI failures are
never a reason to relax them.

- **NEVER weaken a guard to fix a build or test.** In particular, do not
  turn fail-closed behavior into fail-open (I4), do not vary the uniform
  denial text `Bug {id} is not accessible through this server` between
  denied and nonexistent bugs (I2), and do not surface filtered/dropped
  result counts to the client (I3). If a guard blocks a test, fix the test
  or the design — not the guard.
- The guard policy comes only from the operator's TOML file at startup and
  is immutable at runtime (I1). **The policy file must never become
  readable or writable through MCP** — no tool may expose rule names or
  match criteria, and no tool may create, modify, or point the server at a
  policy file.
- CLI/env flags may only tighten policy, never loosen it (I9).
- The Bugzilla API key must never appear in logs, error messages, or tool
  results; sanitize reqwest errors with `.without_url()` (I12). Never log
  secret material of any kind.
- In read-only mode, and for `global.disabled_tools`, write tools are
  removed from the tool listing (`ToolRouter::remove_route`), not merely
  made to error (I13).

## DESIGN.md Records Deliberate Decisions

docs/DESIGN.md is the sole design authority. It records decisions that may
look like accidents but are deliberate (for example the strict
`allow_private_comments = false` default, I5, and the absence of any
header-echo tool, I10); convenience, precedent, or other implementations
are never a justification for undoing them.

## Rust Style and APIs

- Follow `rustfmt`; use idiomatic ownership and borrowing rather than
  cloning to resolve a lifetime issue by default.
- Public items need rustdoc that explains purpose, relevant errors, and
  behavioral constraints. Keep crate documentation accurate.
- Return errors with actionable context (`anyhow` with context in the
  core crate). Do not use `unwrap`, `expect`, or panics in recoverable
  production paths.
- Keep `unsafe` forbidden. Do not weaken workspace lint configuration
  merely to silence a new warning.
- Prefer small, focused functions and exhaustive `match` expressions for
  externally meaningful enums (`Capability`, `Action`, `Access`).

## Async and Networking

- Do not block Tokio worker threads with synchronous I/O, sleeps, or
  process calls. Bound network operations with the client's configured
  timeout.
- Tracing goes to stderr always — stdout belongs to the stdio transport.

## Tests and Dependencies

- Add focused unit tests alongside changed modules (`policy.rs`,
  `guard.rs`); use wiremock for HTTP-level integration tests in
  `crates/bugwarden-core/tests/`. The guard test list in DESIGN.md
  ("Testing") is the minimum bar, not a ceiling.
- A dependency change must update `Cargo.lock`, preserve the MSRV, and pass
  `cargo deny check`. Prefer the smallest compatible version change; do not
  run a broad `cargo update` as part of an unrelated change.
- `typos` runs as its own workflow and is not part of the four verification
  commands; `typos.toml` is an allowlist of deliberate spellings, never a
  mask for a real typo.
