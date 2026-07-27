# Security Policy

## Reporting a vulnerability

Please report suspected security vulnerabilities privately to
**martin@pluskal.org**. Do not open a public issue for a security report.

This applies in particular to **guard bypasses**: any way to make bugwarden
reveal a policy-denied bug's existence or content, leak filtered-result
counts, expose policy rule names or match criteria, obtain private comments
against policy, reach a write tool in read-only mode, or extract the
Bugzilla API key from logs, errors, or tool results.

## Scope

bugwarden exposes a Bugzilla instance over MCP behind operator-controlled
security guards. The guards are defined as invariants I1–I13 in
`docs/DESIGN.md`; security-relevant areas include fail-closed
classification, the uniform denial response, silent search filtering,
private-comment gating, read-only/disabled-tool enforcement, and API-key
handling. The dependency tree is gated in CI by `cargo-deny` (RUSTSEC
advisories, license and source policy), and the code is scanned by CodeQL.

## Supported versions

The latest release from `main` is supported.
