//! # bugwarden-core
//!
//! Guard policy engine and async Bugzilla REST client for the `bugwarden` MCP
//! server. This crate is transport-agnostic and MUST NOT depend on rmcp, axum,
//! clap, or any MCP/transport crate (see `docs/DESIGN.md`); the dependency
//! direction is `bugwarden -> bugwarden-core`, never the reverse.
//!
//! Modules:
//!
//! - [`policy`] — the operator-controlled guard policy: TOML schema, the
//!   case-insensitive glob matcher, and per-bug classification of a
//!   [`policy::BugMeta`] into an [`policy::Access`] decision. The policy is
//!   loaded once at startup and is immutable at runtime (invariant I1).
//! - [`guard`] — runtime enforcement on top of the policy: the batched
//!   classification fetch, the uniform denial text (I2), the redacted
//!   summary projection, silent search-result filtering (I3), and
//!   private-comment gating (I5). All paths fail closed (I4).
//! - [`client`] — minimal async Bugzilla REST client (reqwest + rustls,
//!   aws-lc-rs provider, OS trust store via `rustls-platform-verifier`, with
//!   `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` honored). Errors are sanitized so
//!   the API key can never leak through them (I12).

pub mod client;
pub mod guard;
pub mod policy;
