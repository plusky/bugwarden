<p align="center">
  <img src="assets/logo.svg" alt="bugwarden logo" width="180">
</p>

# bugwarden

**bugwarden** is a Model Context Protocol (MCP) server, written in Rust, with
operator-controlled security guards. It exposes a Bugzilla instance to LLM
clients — querying bugs,
searching, reading comments and history, and (where permitted) updating bugs —
while a policy file that the model can neither see nor change decides, per bug,
what the model is allowed to do.

The Bugzilla REST API already enforces *user* permissions via the API key. What
it cannot do is enforce a *narrower* set of permissions for an AI agent acting
on that user's behalf. bugwarden sits in between: the operator writes a small
TOML policy ("embargoed security bugs are invisible", "on the Security product
the agent may only read summaries and leave comments", "nothing younger than a
week exists"), and every tool call is checked against it before Bugzilla is
touched or data is returned.

## Features

- **Complete Bugzilla tool surface**: bug details, history, comments,
  attachment metadata and content, quicksearch, comment/status/field/
  assignee/CC/dependency updates, duplicate marking, bug filing, attachment
  upload, server info, quicksearch syntax docs, and a bug-summarization
  prompt tool.
- **Guard policy engine**: per-bug `allow` / `deny` / `restrict` decisions
  matched on product, component, group, keyword, status, severity, priority,
  whiteboard, and bug age — with a fine-grained 13-capability vocabulary for
  `restrict`.
- **No existence oracle**: a policy-denied bug is indistinguishable from a
  nonexistent one.
- **Silent search filtering**: denied bugs simply never appear in search
  results; summary-only bugs appear redacted.
- **Minimum-age quarantine**: `min_bug_age_days` makes recently filed bugs
  (the ones most likely to contain not-yet-triaged sensitive data) invisible.
- **Read-only mode and tool disabling** remove write tools from the MCP tool
  listing entirely — clients never see them, rather than seeing them error.
- **Two transports**: streamable HTTP (per-request API key header, suitable for
  shared deployments) and stdio (subprocess launch by a desktop MCP client).
- Single static binary, async throughout (tokio + [rmcp](https://crates.io/crates/rmcp)).

## Security model

### The guard concept

The guard policy is loaded **once, at startup**, from a TOML file passed via
`--policy` (or `BUGWARDEN_POLICY`). It lives on the operator's filesystem. The
MCP client — i.e. the model — has no tool to read it, list its rules, or
modify it. `mcp_server_info` intentionally exposes only coarse facts: the rule
count, the default action, `min_bug_age_days`, whether the server is
read-only, and which tool names are disabled. Rule names and match criteria
are never revealed.

Every tool that takes a bug id first fetches the bug's classification metadata
(product, groups, keywords, creation time, …) and evaluates the policy
**before** any side effect happens or any data is returned. The only exception
is `bug_url`, which computes a URL string locally and contacts nothing.

### Invariants

- **Uniform denial.** A denied bug and a nonexistent bug produce the exact
  same response: `Bug {id} is not accessible through this server`. No wording
  or detail difference can be used as an existence oracle for embargoed bugs.
- **Silent search filtering.** Search results are post-filtered through the
  policy; the client is never told how many results were dropped or that
  filtering happened at all. (Server-side debug logs do record it for the
  operator.)
- **Fail closed.** If the classification fetch fails, if a bug is absent from
  the response, or if a rule cannot be decided because the bug object did not
  carry a field that rule asks about, the bug is treated as denied — never as
  allowed.
- **Private-comment gate.** Private comments are returned only when the policy
  sets `allow_private_comments = true` **and** the individual call opts in
  with `include_private = true`. Either alone is not enough.
- **Custom fields cannot smuggle writes.** `update_bug_fields.custom_fields`
  accepts only keys starting with `cf_`; anything else (e.g. `groups`, `cc`,
  `assigned_to`) is rejected before Bugzilla is contacted.
- **The API key never leaks.** The Bugzilla API key is never written to logs,
  error messages, or tool results; HTTP errors are sanitized so that a key
  passed as a URL query parameter cannot appear in error text.
- **CLI can only tighten.** `--read-only` ORs into the policy's read-only
  flag; there is no CLI switch that loosens the policy.

### Deliberate omissions and strict defaults

- **No header-echo tool.** Incoming request headers — including the API-key
  header — are never exposed to the model.
- **Private comments default to off.** The default policy has
  `allow_private_comments = false`, so a policy file is required to enable
  them.
- **`update_bug_fields` custom fields are restricted** to `cf_*` keys as
  described above.

## Installation / build

```bash
git clone https://github.com/plusky/bugwarden
cd bugwarden
cargo build --release
# binary at target/release/bugwarden
```

The repository pins its Rust toolchain via `rust-toolchain.toml`; `cargo`
picks it up automatically (rustup-managed installs). Any recent stable Rust
works if you build without the pin.

## Usage

> **Note:** some Bugzilla deployments protect their interactive host with an
> anti-bot challenge that rejects API clients regardless of credentials. If
> tools fail with "response body is not valid JSON", check whether the
> instance offers a dedicated API host (for example `apibugzilla.suse.com`
> instead of `bugzilla.suse.com`) and point `--bugzilla-server` at that.

### HTTP transport (default)

The server listens on `http://<host>:<port>/mcp`. Each client request carries
the Bugzilla API key in an HTTP header (default header name: `ApiKey`), so one
server can serve multiple users with their own keys:

```bash
bugwarden \
  --bugzilla-server https://bugzilla.opensuse.org \
  --policy /etc/bugwarden/policy.toml \
  --host 127.0.0.1 --port 8000
```

MCP client configuration (exact format varies by client):

```json
{
  "mcpServers": {
    "bugzilla": {
      "url": "http://127.0.0.1:8000/mcp",
      "headers": {
        "ApiKey": "YOUR_BUGZILLA_API_KEY"
      }
    }
  }
}
```

The header name is configurable with `--api-key-header`. For Bugzilla
instances that reject the `api_key` query parameter and require
`Authorization: Bearer` (e.g. Red Hat Bugzilla), add `--use-auth-header` —
this affects only server-to-Bugzilla authentication, not the client-facing
header.

### stdio transport

For MCP clients that launch the server as a subprocess and speak over
stdin/stdout. There are no per-request HTTP headers here, so the API key must
be provided up front via `--api-key` or `BUGZILLA_API_KEY` (starting without
one is an error):

```bash
BUGZILLA_API_KEY=your_api_key \
  bugwarden \
  --bugzilla-server https://bugzilla.opensuse.org \
  --transport stdio \
  --policy /etc/bugwarden/policy.toml
```

MCP client configuration:

```json
{
  "mcpServers": {
    "bugzilla": {
      "command": "/usr/local/bin/bugwarden",
      "args": [
        "--bugzilla-server", "https://bugzilla.opensuse.org",
        "--transport", "stdio",
        "--policy", "/etc/bugwarden/policy.toml"
      ],
      "env": {
        "BUGZILLA_API_KEY": "YOUR_BUGZILLA_API_KEY"
      }
    }
  }
}
```

## CLI reference

Command-line arguments take precedence over environment variables.

| Flag | Environment variable | Default | Description |
|------|---------------------|---------|-------------|
| `--bugzilla-server <URL>` | `BUGZILLA_SERVER` | *required* | Base URL of the Bugzilla server (e.g. `https://bugzilla.opensuse.org`) |
| `--transport <http\|stdio>` | `MCP_TRANSPORT` | `http` | MCP transport. `stdio` is for subprocess launches by an MCP client; `http` exposes a network endpoint at `/mcp` |
| `--host <ADDRESS>` | `MCP_HOST` | `127.0.0.1` | Listen address (http transport only) |
| `--port <PORT>` | `MCP_PORT` | `8000` | Listen port (http transport only) |
| `--api-key-header <NAME>` | `MCP_API_KEY_HEADER` | `ApiKey` | HTTP header name in which clients send the Bugzilla API key (http transport only) |
| `--api-key <KEY>` | `BUGZILLA_API_KEY` | — | Bugzilla API key. **Required** for `--transport stdio`; with `http` it is ignored with a warning (clients send the key per request) |
| `--use-auth-header` | — | `false` | Authenticate to Bugzilla with `Authorization: Bearer <key>` instead of the `api_key` query parameter |
| `--read-only` | `MCP_READ_ONLY` | `false` | Disable all write tools. Tighten-only: ORed with the policy's `global.read_only`; cannot re-enable writes a policy forbids |
| `--policy <PATH>` | `BUGWARDEN_POLICY` | — | Path to the guard policy TOML. Without it, an allow-all policy applies (with private comments off) |

## Policy file reference

The policy is strict TOML: **unknown keys anywhere are a startup error**, as
is a `restrict` rule without capabilities, an `allow`/`deny` rule *with*
capabilities, or `default_action = "restrict"`. On Unix, bugwarden logs a
warning at startup if the policy file is group- or other-writable.

A complete, commented example ships in
[`examples/policy.toml`](examples/policy.toml).

### Top level

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `default_action` | `"allow"` \| `"deny"` | `"allow"` | Applied when no rule matches a bug. Must not be `"restrict"` (a catch-all `restrict` rule expresses that instead) |

### `[global]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `min_bug_age_days` | integer | `0` (disabled) | Bugs created less than N days ago are **invisible** — treated exactly like nonexistent bugs, evaluated before any rule. A bug whose `creation_time` is missing or unparsable is denied (fail closed) |
| `allow_private_comments` | boolean | `false` | Master switch for **all** private content: comments, attachment metadata, and attachment downloads. Even when `true`, each call must also pass `include_private = true`. On an attachment download a *missing* privacy flag counts as private |
| `read_only` | boolean | `false` | Strip write capabilities from every grant and remove write tools from the tool listing. The `--read-only` flag ORs into this |
| `disabled_tools` | array of strings | `[]` | Tool names to remove from the tool listing entirely |
| `max_attachment_bytes` | integer | `2097152` (2 MiB) | Largest attachment `download_attachment` may return (decoded size). `0` removes the cap. Attachment content is embedded base64 in the tool result and lands in the model's context — raise deliberately |

### `[[rule]]`

Rules are evaluated **top to bottom; the first rule whose matcher matches the
bug wins** and later rules are ignored. If no rule matches, `default_action`
applies. Put your most specific (usually most restrictive) rules first.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | *required* | Rule identifier (server-side logs only; never shown to clients) |
| `description` | string | `""` | Free-form operator documentation |
| `match` | table | `{}` (matches every bug) | Match criteria, see below |
| `action` | `"allow"` \| `"deny"` \| `"restrict"` | *required* | `allow` grants all capabilities, `deny` grants none, `restrict` grants exactly `capabilities` |
| `capabilities` | array of capability strings | `[]` | Only for `action = "restrict"`, where at least one is required. Must be empty/absent for `allow` and `deny` |

#### `match` criteria

All criteria present in a matcher must hold (**AND**). Within a single list,
any element may match (**OR**). An empty matcher matches every bug — a rule
with no `match` is a catch-all. To express "criterion A **or** criterion B",
write two consecutive rules.

| Key | Type | Matched against |
|-----|------|-----------------|
| `products` | array of globs | the bug's product |
| `components` | array of globs | any of the bug's components |
| `groups` | array of globs | any of the bug's group names |
| `keywords` | array of globs | any of the bug's keywords |
| `statuses` | array of globs | the bug's status |
| `severities` | array of globs | the bug's severity |
| `priorities` | array of globs | the bug's priority |
| `whiteboard_contains` | array of strings | case-insensitive substring search in the whiteboard |
| `summary_contains` | array of strings | case-insensitive substring search in the bug's one-line summary |
| `group_restricted` | boolean | `true` matches bugs readable only through at least one Bugzilla group, `false` matches world-readable bugs |
| `younger_than_days` | integer | matches bugs created within the last N days |

#### Unreadable metadata

Every criterion needs a field the bug object may not carry — absent, `null`,
of an unexpected type, or a list with an element the parser cannot read. Such
a field is **unknown**, and a rule that consults one is undecidable: it neither
holds nor fails.

bugwarden resolves an undecidable rule by **denying the bug**, whatever the
rule's action. A `deny` rule denies because the bug may well be what it was
written to catch. An `allow` or `restrict` rule denies too — it may not grant
access on data nobody could check, and it may not simply be skipped either,
because skipping would hand the bug to a later rule or to `default_action`. So
unreadable metadata never buys a bug more access than readable metadata would.

Two things this deliberately does *not* do. A criterion that already failed
definitively wins over an unknown one, so a rule ruled out by another criterion
stays ruled out. And only the fields a rule actually consults matter — a
missing whiteboard is irrelevant to a rule that never mentions the whiteboard.
A field that is present but empty (`""`, `[]`) is knowledge, not ignorance, and
is matched normally.

#### Glob syntax

Globs match the whole value, case-insensitively. `*` matches any (possibly
empty) substring; every other character is literal. There are no other
metacharacters. Examples: `embargo*`, `*security*`, `SUSE *`.

#### Capabilities

Thirteen capabilities exist. `read` implies `summary`; nothing else is
implied.

> **Upgrading from a version without `create`/`attach`:** the capability set
> grew from eleven to thirteen, and `allow` (rules and
> `default_action = "allow"` alike) always grants the **full** set. A policy
> written before these capabilities existed therefore starts permitting bug
> filing and attachment upload the moment the server is upgraded, with no
> change to the policy file. To keep the old behaviour, either add
> `disabled_tools = ["create_bug", "add_attachment"]` under `[global]`, or
> replace `allow` grants with `restrict` rules listing exactly the
> capabilities you mean. Read-only deployments are unaffected (both new
> capabilities are writes).

| Capability | Kind | Grants |
|------------|------|--------|
| `read` | read | full bug details (implies `summary`) |
| `summary` | read | redacted summary-only view (id, summary, status, resolution, product, component, severity, priority, creation/last-change time) |
| `comments` | read | reading comments (also needed by `summarize_bug`) |
| `history` | read | reading the bug's change history |
| `attachments` | read | listing attachment metadata and downloading attachment content |
| `comment` | write | adding a comment |
| `status` | write | changing status/resolution, marking duplicates |
| `fields` | write | changing priority, severity, resolution, `cf_*` custom fields |
| `assign` | write | changing the assignee |
| `cc` | write | modifying the CC list |
| `deps` | write | changing blocks/depends_on |
| `create` | write | filing a new bug — judged against the bug *as requested*, so a rule that hides a product by name also refuses filing into it. The request's `groups` claim is never trusted (Bugzilla adds mandatory groups server-side), so **a policy whose rules consult `groups` or `group_restricted` refuses all bug filing** |
| `attach` | write | uploading an attachment to a bug |

When the server is read-only (policy or CLI), the eight write capabilities
are stripped from every grant, including from `allow` rules and the default
action.

## Tool reference

| Tool | What it does | Required capability |
|------|--------------|---------------------|
| `bug_info` | Details for a set of bug ids. Per id: full details with `read`, redacted summary with `summary`, otherwise a uniform "not accessible" entry | `read` / `summary` |
| `bug_history` | Change history of a bug, optionally only entries newer than a timestamp | `history` |
| `bug_comments` | Comments on a bug; private comments only per the private-comment gate | `comments` |
| `bugs_quicksearch` | Bugzilla [quicksearch](https://bugzilla.readthedocs.io/en/latest/using/finding.html#quicksearch) — the `status` filter (default `ALL`) is prefixed to the query, and under any non-empty status a number in the query is content-matched, so it also matches bugs that merely mention it; with an empty `status` the query goes to Bugzilla bare, where a query of nothing but numbers is an exact id lookup (use `bug_info` for an exact set of known ids; an all-ids query gets an advisory note saying so). Results are silently policy-filtered (denied dropped, summary-only redacted) | per result: `read` / `summary` |
| `summarize_bug` | Returns a summarization prompt built from the bug's public comments | `comments` |
| `list_attachments` | Attachment metadata (never attachment content) | `attachments` |
| `download_attachment` | Content of one attachment (raster images as image content, everything else as a base64 blob resource), capped by `max_attachment_bytes`; private attachments need the private-content double opt-in and, on download, a *missing* privacy flag counts as private | `attachments` on the owning bug |
| `add_comment` | Add a comment to a bug | `comment` |
| `update_bug_status` | Change status/resolution (CLOSED requires a resolution) | `status` |
| `assign_bug` | Set the assignee | `assign` |
| `update_bug_fields` | Update priority/severity/resolution and `cf_*` custom fields | `fields` |
| `update_bug_dependencies` | Add/remove blocks and depends_on entries | `deps` |
| `add_cc_to_bug` | Add an email to the CC list | `cc` |
| `mark_as_duplicate` | Close a bug as DUPLICATE of another | `status` on the bug **and** at least `summary` on the duplicate target |
| `create_bug` | File a new bug; the request is policy-checked *as described* before anything is created. A policy refusal and a Bugzilla-side failure return the same refusal text at the same cost, so a failed create never says which of the two refused, or why | `create` on the bug as requested |
| `add_attachment` | Upload a base64-encoded attachment to a bug, capped by `max_attachment_bytes` (decoded size) | `attach` on the target bug |
| `bug_url` | Compute `{server}/show_bug.cgi?id={id}` locally | none (contacts nothing) |
| `bugzilla_server_info` | Bugzilla version, extensions, timezone, time, parameters | none |
| `quicksearch_syntax` | Bugzilla's quicksearch syntax documentation (HTML) | none |
| `mcp_server_info` | bugwarden version, Bugzilla URL, transport, coarse policy summary | none |

## Roadmap

- **OBS / openSUSE packaging** for installation via zypper.

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
