<p align="center">
  <img src="https://raw.githubusercontent.com/plusky/bugwarden/main/assets/logo.svg" alt="bugwarden logo" width="180">
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
  whiteboard, summary, group-restrictedness, bug age, and authorship (whether
  the requesting account filed the bug) — with a fine-grained 13-capability
  vocabulary for `restrict`.
- **No existence oracle**: a policy-denied bug is indistinguishable from a
  nonexistent one.
- **Silent search filtering**: denied bugs simply never appear in search
  results; summary-only bugs appear redacted.
- **Minimum-age quarantine**: `min_bug_age_days` makes recently filed bugs
  (the ones most likely to contain not-yet-triaged sensitive data) invisible.
- **Read-only mode and tool disabling** remove write tools from the MCP tool
  listing entirely — clients never see them, rather than seeing them error.
- **Audit stream**: an operator-only JSONL record of every tool call — the
  guard's verdict, the deciding rule, the bug ids it suppressed — with
  fail-closed modes that hold back further work while records cannot be
  persisted. The stream is the operator's half of the bargain the guard
  makes with the client, and no MCP surface can reach it.
- **Two transports**: streamable HTTP (per-request API key header, or a
  server-held key via `--api-key-file` for fleet deployments) and stdio
  (subprocess launch by a desktop MCP client).
- Single static binary, async throughout (tokio + [rmcp](https://crates.io/crates/rmcp)),
  shipping with a man page and bash/zsh/fish completions.

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
  filtering happened at all. The operator is: a server-side debug log
  records it, and an audited deployment gets the scan's counts and the
  withheld ids in the audit stream.
- **Fail closed.** If the classification fetch fails, if a bug is absent from
  the response, or if a rule consulted for the operation being decided cannot
  be decided because the bug object did not carry a field that rule asks
  about — or, for the identity criterion `created_by_me`, because the
  bug–caller relationship could not be established — the bug is treated as
  denied — never as allowed. (A rule scoped away from the operation via
  `operations` is not consulted at all — scoping changes which rules run,
  never how a consulted rule resolves.)
- **Private-comment gate.** Private comments are returned only when the policy
  sets `allow_private_comments = true` **and** the individual call opts in
  with `include_private = true`. Either alone is not enough.
- **Custom fields cannot smuggle writes.** `update_bug_fields.custom_fields`
  and `create_bug.custom_fields` accept only keys starting with `cf_`;
  anything else (e.g. `groups`, `cc`, `assigned_to`) is rejected before
  Bugzilla is contacted.
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
- **`update_bug_fields` and `create_bug` custom fields are restricted** to
  `cf_*` keys as described above.

## Installation

### openSUSE (zypper)

bugwarden is packaged in openSUSE Tumbleweed:

```bash
sudo zypper install bugwarden
```

For other openSUSE distributions (Leap 16.x, Slowroll), packages are built in
the [`devel:tools`](https://build.opensuse.org/package/show/devel:tools/bugwarden)
project on the openSUSE Build Service.

The package installs worked-example configuration files —
`/etc/bugwarden/policy.toml` (guard policy) and `/etc/bugwarden/audit.toml`
(audit stream) — marked `%config(noreplace)`, so local edits survive package
upgrades. Neither is loaded implicitly: the server reads a policy only when
one is named via `--policy` / `BUGWARDEN_POLICY`, and an audit configuration
only via `--audit-config` / `BUGWARDEN_AUDIT_CONFIG`, so installing the
package does not by itself activate anything.

### crates.io (cargo)

```bash
cargo install bugwarden
```

This installs the `bugwarden` binary into `~/.cargo/bin`. Unlike the openSUSE
package it ships no configuration files — copy
[`examples/policy.toml`](examples/policy.toml) somewhere and name it via
`--policy`.

### From source

```bash
git clone https://github.com/plusky/bugwarden
cd bugwarden
cargo build --release
# binary at target/release/bugwarden
```

The repository pins its Rust toolchain via `rust-toolchain.toml`; `cargo`
picks it up automatically (rustup-managed installs). Any recent stable Rust
works if you build without the pin. The build compiles `aws-lc-sys` from
source, so it needs a C toolchain (a C compiler and `cmake`) as well as
Rust — this applies to `cargo install bugwarden` too, not only a source
build.

### Man page and shell completions

Every release tarball carries the generated CLI assets next to the binary,
for a distribution package or a manual install to place:

| Path in the tarball | Conventional destination |
|---------------------|--------------------------|
| `man/bugwarden.1` | `/usr/share/man/man1/bugwarden.1` |
| `completions/bugwarden.bash` | `/usr/share/bash-completion/completions/bugwarden` |
| `completions/_bugwarden` | `/usr/share/zsh/site-functions/_bugwarden` |
| `completions/bugwarden.fish` | `/usr/share/fish/vendor_completions.d/bugwarden.fish` |

Man page and completions alike are derived from the clap command itself —
including the man page's `ENVIRONMENT` section, so every flag with an
environment variable is listed exactly once — by a second binary behind the
`gen` cargo feature:

```bash
cargo run --locked -p bugwarden --features gen --bin bugwarden-gen
# or, to write somewhere else:
cargo run --locked -p bugwarden --features gen --bin bugwarden-gen -- /tmp/out
```

Without an argument the generator rewrites the committed copies under
`crates/bugwarden/`; with one it writes `man/` and `completions/` under that
directory instead. CI regenerates and diffs them, so the committed assets
cannot drift from the CLI. The feature gates only this generator — the
server binary never links `clap_complete` or `clap_mangen`, and a plain
`cargo build` skips it.

### TLS trust anchors and proxies

bugwarden validates the Bugzilla server's certificate against the **OS
trust store**, not a bundled root set. A Bugzilla instance behind a
corporate or internal CA works as soon as that CA is installed
system-wide — no bugwarden-side configuration is needed. The corollary: an
environment with no CA bundle at all — a `scratch` or `distroless` image,
some minimal base images — fails every HTTPS request to Bugzilla with a TLS
handshake error. Install `ca-certificates` in the image, or mount the
host's bundle into it:

```dockerfile
FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY bugwarden /usr/local/bin/bugwarden
ENTRYPOINT ["/usr/local/bin/bugwarden"]
```

`HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` from the environment are honored
for outbound Bugzilla traffic. Every request to Bugzilla — authenticated
REST calls and the unauthenticated quicksearch-syntax page alike — carries
`User-Agent: bugwarden/<version> (+https://github.com/plusky/bugwarden)`, so
the instance's access log names this build rather than an anonymous HTTP
client. The header carries nothing else: no key material, no policy path,
no host.

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

#### Server-held key mode (fleet deployments)

With `--api-key-file` the Bugzilla API key belongs to the *server*: every
request is served with the key read from that file, clients present no
credential at all, and the per-request header is not consulted — a request
that does carry one is served with the server's key, and the header value is
never read. There is **no fallback between the two modes in either
direction** (handing clients the real key would let them bypass the guard by
talking to Bugzilla directly). This fits deployments where the key is
provisioned as a container secret or a systemd credential
(`LoadCredential=bugzilla-key:/etc/bugwarden/bugzilla-key` plus
`--api-key-file ${CREDENTIALS_DIRECTORY}/bugzilla-key`):

```bash
bugwarden \
  --bugzilla-server https://bugzilla.opensuse.org \
  --policy /etc/bugwarden/policy.toml \
  --api-key-file /run/secrets/bugzilla-key \
  --host 127.0.0.1 --port 8000
```

The file's content is trimmed, so a trailing newline is fine; an empty or
unreadable file is a startup error naming the path (never its contents). The
file is read exactly once, at startup — rotating the key requires a restart.
Keep it mode 0600: bugwarden warns when group or others can access it.

One policy consequence to know: in this mode every client authenticates to
Bugzilla — and resolves identity — as the service account that owns the key,
so a policy rule matching on `created_by_me` describes that one account's
bug reports for *all* clients, not each caller's own. bugwarden warns at
startup when server-held mode meets such a policy.

### stdio transport

For MCP clients that launch the server as a subprocess and speak over
stdin/stdout. There are no per-request HTTP headers here, so the API key must
be provided up front via `--api-key` / `BUGZILLA_API_KEY` or `--api-key-file`
(starting without one is an error):

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

### MCP protocol revisions

bugwarden serves four revisions of the Model Context Protocol —
`2024-11-05`, `2025-03-26`, `2025-06-18` and `2025-11-25` — and offers
`2025-11-25` when a client asks for something outside that set. The list is
pinned rather than inherited from the SDK, so a dependency bump cannot
quietly widen or narrow what a deployment speaks. In the handshake the
server names itself and its version — `bugwarden` and the release it was
built from — never the SDK's.

Every session must complete the `initialize` handshake. A request that
carries a protocol revision in its own `_meta` instead — the handshake-free
lifecycle — is refused whatever revision it names, because a server that
answered it would be talking to a client it never greeted, and no audit
record could say who that was.

The advertised capability set is tools only: bugwarden registers no MCP
prompts and no MCP resources. `summarize_bug` is a tool that returns prompt
text, not an MCP prompt.

## CLI reference

Command-line arguments take precedence over environment variables.

| Flag | Environment variable | Default | Description |
|------|---------------------|---------|-------------|
| `--bugzilla-server <URL>` | `BUGZILLA_SERVER` | *required* | Base URL of the Bugzilla server (e.g. `https://bugzilla.opensuse.org`) |
| `--transport <http\|stdio>` | `MCP_TRANSPORT` | `http` | MCP transport. `stdio` is for subprocess launches by an MCP client; `http` exposes a network endpoint at `/mcp` |
| `--host <ADDRESS>` | `MCP_HOST` | `127.0.0.1` | Listen address (http transport only) |
| `--port <PORT>` | `MCP_PORT` | `8000` | Listen port (http transport only) |
| `--allowed-hosts <HOST>` | — | — | Hostname or `host:port` authority accepted in an inbound `Host` header (http transport only). Repeatable; each occurrence adds one host. Without it no `Host` validation happens, so a client may address the server by any name |
| `--api-key-header <NAME>` | `MCP_API_KEY_HEADER` | `ApiKey` | HTTP header name in which clients send the Bugzilla API key (http transport only). Not consulted in server-held key mode |
| `--api-key <KEY>` | `BUGZILLA_API_KEY` | — | Bugzilla API key. **Required** for `--transport stdio` unless `--api-key-file` provides it; with `http` it is ignored with a warning (clients send the key per request — use `--api-key-file` for a server-held key) |
| `--api-key-file <PATH>` | `BUGZILLA_API_KEY_FILE` | — | Path to a file holding the Bugzilla API key (container secret, systemd `LoadCredential` path). Mutually exclusive with `--api-key`; an empty value counts as unset. Over `http` this selects server-held key mode: every request is served with this key and the per-request header is not consulted |
| `--use-auth-header` | — | `false` | Authenticate to Bugzilla with `Authorization: Bearer <key>` instead of the `api_key` query parameter |
| `--read-only` | `MCP_READ_ONLY` | `false` | Disable all write tools. Tighten-only: ORed with the policy's `global.read_only`; cannot re-enable writes a policy forbids. As an environment variable it takes the literal `true` or `false` — `1`, `yes` and an empty value are a usage error, not a synonym |
| `--policy <PATH>` | `BUGWARDEN_POLICY` | — | Path to the guard policy TOML. Without it, an allow-all policy applies (with private comments off and the 2 MiB attachment cap still in force) |
| `--audit-config <PATH>` | `BUGWARDEN_AUDIT_CONFIG` | — | Path to the audit stream configuration TOML (worked example in [`examples/audit.toml`](examples/audit.toml)). Without it, no audit stream is written. Records carry W3C trace ids when the client sends a `traceparent` in the request's `_meta`, enabling correlation with client-side traces |
| — | `RUST_LOG` | `info` | Tracing filter for the diagnostic log, which always goes to **stderr** — stdout belongs to the stdio transport. An unparsable value falls back to `info` |

An empty value counts as unset for `--api-key` and `--api-key-file` only, so
`BUGZILLA_API_KEY_FILE=` in a unit file leaves the two key modes unaffected
rather than erroring (under stdio it then leaves no key source at all, which
is a startup error of its own). An empty `BUGWARDEN_POLICY` or
`BUGWARDEN_AUDIT_CONFIG` is a usage error.

Exit status: `0` on clean shutdown, `1` on a startup or runtime failure (an
unreadable policy or audit configuration, a key misconfiguration, a Bugzilla
client or transport error), `2` on a command-line usage error.

## Policy file reference

The policy is strict TOML: **unknown keys anywhere are a startup error**, as
is a `restrict` rule without capabilities, an `allow`/`deny` rule *with*
capabilities, or `default_action = "restrict"`. On Unix, bugwarden logs a
warning at startup if the policy file is group- or other-writable.

**Upgrading with an existing policy:** rule names are now checked at startup
(see `name` below), so a policy file that started an older bugwarden can stop
this one from starting at all — if it names a rule `default`,
`min_bug_age_days` or `unavailable`, ends a name with `:unreadable-metadata`,
leaves a name blank, or uses one name twice. The error names the offending
rule; rename it and the file loads unchanged. Nothing else about the file's
meaning changed.

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
| `max_attachment_bytes` | integer | `2097152` (2 MiB) | Largest attachment `download_attachment` may return, and the same ceiling on what `add_attachment` may upload — both measured on the decoded size. `0` removes this cap. Over http the transport's POST body limit is sized from this value — base64 expansion plus 1 MiB of headroom for the rest of the call, clamped to [4 MiB, 64 MiB] — so a canonical `add_attachment` at this cap fits through it (Bugzilla's own 65535-character comment limit keeps the other arguments well inside the headroom). The clamps mean two values are not honored over http: with `0` the transport keeps its 4 MiB bound, and a cap above ~47 MiB decoded is limited by the 64 MiB ceiling — "no policy cap" and "an enormous policy cap" must not become an unbounded request body. Downloaded content is embedded base64 in the tool result and lands in the model's context — raise deliberately |
| `identity_source` | `"whoami"` \| `"declared"` | `"whoami"` | How `created_by_me` resolves the caller's login. `whoami` calls Bugzilla's `GET /rest/whoami` — a fork/BMO extension absent from stock Bugzilla Core v1. `declared` names an operator-configured login instead (see `identity_login`), verified once at startup against the *stock* `GET /rest/valid_login` endpoint and never looked up again per call — the portable path when the deployment has no identity endpoint at all. See the `created_by_me` row below and "Identity resolution" in `docs/DESIGN.md` |
| `identity_login` | string | none | Required (and must be non-blank) exactly when `identity_source = "declared"`; a hard startup error if set under `identity_source = "whoami"` (it would otherwise be silently ignored). Names the account that owns *this server's* API key, so it is only meaningful under a server-held key (stdio, or http server-held mode) — a startup error under http per-request key custody, where there is no server-held key for it to describe. Bugzilla compares logins case-sensitively (Perl `eq`); declare it exactly as Bugzilla stores it |
| `allow_discovery` | boolean | `false` | Exposes `bugzilla_products` and `bug_fields`, two read-only tools that return this Bugzilla instance's product and bug-field metadata **exactly as Bugzilla returns it to this server's key, never filtered by this guard policy** — filtering the catalog would itself be a way to probe the policy's rules. Leave this off (the default) if product or field names are themselves confidential; `disabled_tools` still works independently once discovery is on. Older bugwarden versions reject a policy using this key at startup (strict parsing fails closed) |

### `[[rule]]`

Rules are evaluated **top to bottom; the first rule whose matcher matches the
bug wins** and later rules are ignored. If no rule matches, `default_action`
applies. Put your most specific (usually most restrictive) rules first.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | *required* | Rule identifier. It reaches the audit stream, where it names the rule that decided a call, and nothing a client can see. Must be non-blank and unique within the file, and may not be one of the names the guard decides under itself — `default`, `min_bug_age_days`, `unavailable`, or anything ending in `:unreadable-metadata` — otherwise an audit record could not say whether your rule or the guard decided. A reserved name, a blank name and a repeated name are each a startup error naming the offending rule. The *collision* checks compare exactly, so `Default`, ` default` and `unreadable-metadata` (no colon) are ordinary names; only the blank check ignores surrounding whitespace |
| `description` | string | `""` | Free-form operator documentation |
| `match` | table | `{}` (matches every bug) | Match criteria, see below |
| `action` | `"allow"` \| `"deny"` \| `"restrict"` | *required* | `allow` grants all capabilities, `deny` grants none, `restrict` grants exactly `capabilities` |
| `capabilities` | array of capability strings | `[]` | Only for `action = "restrict"`, where at least one is required. Must be empty/absent for `allow` and `deny` |
| `operations` | array of `"create"` \| `"access"` | absent (rule applies to every operation) | Scopes the rule to the named operations: `create` is the create gate judging a prospective `create_bug` request, `access` is every classification of an existing bug (retrieval, search filtering, comments, history, attachments, updates). The scope is checked **before** the matcher, so a scoped rule is completely invisible to the operations it does not cover — a create-scoped rule can never hide an existing bug. An explicitly empty list is a startup error, as is a `restrict` rule whose scope and `capabilities` disagree about `create`: a rule scoped to only `create` must grant exactly the `create` capability (the create gate consults nothing else), and a rule scoped away from `create` must not grant it (nothing else consults it). Older bugwarden versions reject a policy using this key at startup (strict parsing — the file fails closed rather than being misread) |

Note that a `restrict` rule's `capabilities` list is the **complete grant**
for every operation the rule covers, not an addition to what other rules or
`default_action` would have granted — that is why a rule granting only
`create` should carry `operations = ["create"]`, so it decides filing without
becoming the first-match rule for reads of the bugs it matches.

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
| `created_by_me` | boolean | whether the caller's account authored the bug, compared case-insensitively to the bug's creator. `true` matches the caller's own reports, `false` everyone else's. How the caller's login is resolved depends on `global.identity_source` (default `whoami`): see the source × custody table below. Either source costs at most one lookup per tool call — `whoami` a fresh `GET /rest/whoami`, `declared` zero HTTP requests, since it was verified once at startup — and none at all under a policy without an access-covering `created_by_me` rule (a rule scoped to `operations = ["create"]` alone never triggers one). An unresolvable identity makes the criterion **unknown**, which denies (see Unreadable metadata); a policy that consults this criterion therefore denies everything it reaches while identity cannot be resolved. In the create gate the prospective bug always counts as created by the caller — no lookup happens there. Older bugwarden versions reject a policy using this key, or `global.identity_source`/`global.identity_login`, at startup (strict parsing fails closed) |

Identity resolution by source and API-key custody:

| `identity_source` | stdio / http server-held key | http per-request key |
|---|---|---|
| `whoami` (default) | verified at startup (`BugWarden::preflight`); one `GET /rest/whoami` per tool call | unverifiable at startup (warns instead); one `GET /rest/whoami` per tool call |
| `declared` | verified once at startup via `GET /rest/valid_login`; **zero** identity requests per tool call | **startup error** — there is no server-held key for the declared login to describe |

`whoami` is a fork/BMO extension absent from stock Bugzilla Core v1;
`valid_login` is documented there, which is what makes `declared` the
portable path on a deployment that has no identity endpoint at all.

#### Unreadable metadata

Every criterion needs a field the bug object may not carry — absent, `null`,
of an unexpected type, or a list with an element the parser cannot read. Such
a field is **unknown**, and a rule that consults one is undecidable: it neither
holds nor fails. One criterion needs more than the bug object:
`created_by_me` also needs the caller's identity, and if either half is
missing — an unreadable creator, or an identity lookup that failed (under
`identity_source = "whoami"`) or does not exist on the deployment — it is
just as undecidable and resolves the same way. A policy consulting identity
therefore denies everything its identity rules are consulted for while
identity is unavailable — including permanently, under `whoami` on a stock
Bugzilla Core v1 deployment that never exposes it; that is deliberate
(treating unknown identity as "does not match" would let a `created_by_me`
deny rule be defeated by breaking `whoami`). `identity_source = "declared"`
sidesteps this on such a deployment: the login is verified once at startup
(`BugWarden::preflight` fails to start rather than serve a blackout) and
never looked up again, so there is no per-call failure mode left. The criterion
cannot widen exposure beyond the credential: Bugzilla enforces its own
permissions on every fetch, so an authorship rule only surfaces bugs the API
key could already read.

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
Likewise, only the rules actually consulted matter: a rule scoped away from
the operation being decided (`operations`) is skipped before its matcher runs,
so its criteria cannot make anything undecidable for that operation.
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
| `fields` | write | changing priority, severity, resolution, summary, URL, whiteboard, version, target milestone, keywords, see-also links, `cf_*` custom fields |
| `assign` | write | changing the assignee |
| `cc` | write | modifying the CC list |
| `deps` | write | changing blocks/depends_on |
| `create` | write | filing a new bug, including `cf_*` custom fields — judged against the bug *as requested*, so a rule that hides a product by name also refuses filing into it. The request's `groups` claim is never trusted (Bugzilla adds mandatory groups server-side), so **a rule consulting `groups` or `group_restricted` refuses every create request that reaches it** — to accept new bugs under such a policy, grant `create` in a rule scoped with `operations = ["create"]` placed before the group-consulting rules; being create-scoped, the grant leaves reads of existing bugs untouched, and without such a grant the policy refuses all bug filing |
| `attach` | write | uploading an attachment to a bug |

When the server is read-only (policy or CLI), the eight write capabilities
are stripped from every grant, including from `allow` rules and the default
action.

## Audit stream

The guard hides things from the client by design: a denied bug looks like a
nonexistent one, filtered search results vanish without a trace, and no rule
is ever named in a response. The audit stream is the other half of that
bargain — the operator's own record of what was asked and what the guard
decided. It carries exactly the facts the client must never see, which is
why it goes only to a local file the operator controls: no MCP surface can
read it, and it is never mixed into the diagnostic stderr stream.

Auditing is off until `--audit-config` / `BUGWARDEN_AUDIT_CONFIG` names a
configuration file; a commented example ships in
[`examples/audit.toml`](examples/audit.toml). Over the http transport,
starting without one logs a warning. Parsing is strict — unknown keys are a
startup error, so a typo cannot silently disable a setting.

### Audit configuration reference

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `path` | string | *required* | The JSONL file. Its parent directory is created mode `0700` if missing, the file mode `0600`, and it is only ever appended to. A symlink at this path is refused at startup |
| `fsync` | boolean | `false` | `sync_data` after every record. `false` already survives a killed process — each record reaches the kernel before the tool response is returned — but only `true` survives power loss, at a latency cost on every call |
| `fail_mode` | `"open"` \| `"closed_writes_denials"` \| `"closed_all"` | derived from the transport: `open` for stdio, `closed_all` for http | What happens to tool calls while records cannot be persisted, see below |
| `rotate_max_bytes` | integer | `67108864` (64 MiB) | Rotate before a record would push the live file past this size, so the bound is hard — with one exception: a single record larger than the limit is written into an empty live file as-is, because rotating an empty file would discard nothing and loop. `0` disables built-in rotation — do that when logrotate owns the file, and never let both rotate it |
| `rotate_keep` | integer | `8` | How many rotated `path.1` … `path.N` files to keep. At least `1` while `rotate_max_bytes` is non-zero, at most `10000`. Shrinking it between runs strands the existing higher-numbered files; bugwarden never deletes those |
| `suppressed_ids` | boolean | `true` | Whether records may name the bug ids the guard withheld. With `false` only the count survives. The ids are precisely the hidden-bug numbers the server exists to withhold, so with `true` the audit file is itself sensitive — anyone who can read it can enumerate hidden bugs |

### Fail modes

A record is written after its tool has run, so the modes govern what happens
*next*: once a write has failed, the sink is known to be failing and the
following calls are held back before they dispatch. The call that first meets
the outage has already reached Bugzilla, so a single write per outage can
land unrecorded — and its caller is told it failed. The `audit_gap` record
that follows recovery is what makes that loss visible.

- **`open`** — keep serving. Lost records surface later as an `audit_gap`
  record carrying the drop count, but what was asked during the outage is
  gone. Availability over accountability.
- **`closed_writes_denials`** — reads the guard fully allowed still proceed
  unaudited; write tools, and any call where the guard suppressed, denied or
  refused something, are refused until records persist again.
- **`closed_all`** — every tool call is refused, and the `initialize`
  handshake with it, until its record can be persisted. Accountability over
  availability: an unmonitored full disk takes the deployment down, since no
  session can even open.

Refusals under the closed modes reuse each tool's ordinary failure wording,
so a refused call is not distinguishable from an ordinary failure, and a
protocol-level error from the router stands under every mode rather than
being reshaped into one. The one place an outage is legible to a client is
the `closed_all` handshake, which is declined with an explicit "audit
unavailable" — a session that cannot be recorded is not opened, and saying
so beats a mystery. With auditing off, on, or failing open, tool responses
are byte-identical.

### Records

One JSON object per line, schema version 1, in three kinds:

- **`initialize`** — a client opened a session; carries the client's
  self-declared name and version and the *negotiated* protocol revision.
  Written unconditionally, with no knob to suppress it.
- **`tool_call`** — exactly one per tool invocation, including calls that
  were denied, refused, or aimed at a tool name that does not exist. The
  tool listing is deliberately not recorded.
- **`audit_gap`** — records were lost; carries how many and whether the
  cause was a write or a rotation error. The gap is reported in the stream
  itself, so silent loss is impossible to miss.

Every record carries `v`, a millisecond-precision UTC `ts`, a per-process
monotonic `seq` (the ordering authority — file order equals `seq` order),
and a `session` naming the transport, the session id and, over http, the
peer address. A `tool_call` adds the client, the request (tool name, request
id, parameters), the outcome class and duration, and — for the tools that
consult the guard — a `guard` object:

| `guard` field | Meaning |
|---------------|---------|
| `verdict` | `served`, `served_filtered`, `denied` or `refused`; the worst verdict of the call wins |
| `rule` | What decided a per-bug assessment. Alongside the policy's own rule names the guard reports its own: `default` when no rule matched — a default-decided call records that literal, never an absent field — `min_bug_age_days` for the age quarantine, `<name>:unreadable-metadata` for a *granting* rule whose verdict hinged on metadata that could not be read (an undecidable deny rule keeps its plain name, having denied for its own reason), `unavailable` for a bug the classification fetch could not reach. A policy naming one of its own rules `default` — or any of the others — is a startup error, so this field says what decided *and* what kind of thing it was. Absent only where no single rule decided: a refusal, the pre-dispatch gate, a search, either arm of the create gate, an id the guard could not assess, and a withheld attachment. A tool removed from the router (read-only mode, `disabled_tools`, discovery off) records no `guard` object at all |
| `policy_hash` | `sha256:` over the raw policy file bytes, so a record says which policy text judged the call. Absent when no policy file is loaded |
| `suppressed_count` | How much the response withheld, in total: bug ids on a search or a multi-bug read, plus the private comments and attachment metadata the private-content gate removed. The two never overlap — a call reads its bug ids off the content that survived filtering — so the field is their sum, and it is the authoritative number: never infer a count from the id list, which names bugs only and can be switched off entirely. Two ids under a count of five means three withheld items had no bug id of their own |
| `suppressed_ids` | The withheld bug ids, subject to the `suppressed_ids` switch |
| `redacted_fields` | Names of what a response redacted, never values — `summary_view` for a bug served through the redacted summary view |
| `scan` | Present on every served search, carrying how many rows the window scanned and how many it dropped, so `dropped: 0` is a statement and not an omission; absent on a search that failed and on tools that scan nothing. The counts are recorded whatever the `suppressed_ids` switch says: counts are not ids |

A `tool_call` also carries `trace` when the client sends a valid W3C
`traceparent` in the request's `_meta`, which makes the call correlatable
with the client's own trace. The parse is strict and silent: a malformed
value leaves the field absent, is never logged, and never influences the
guard or the response. Schema v1 reserves an `upstream` field for
Bugzilla-side timings; nothing emits it yet, so do not build on it.

### What can never appear in a record

The schema is closed — fixed structs, fixed vocabularies — and it has no
field for the Bugzilla API key, for request headers, or for free-text bug
content. Nothing fetched *from* Bugzilla is written: a tool result is not a
parameter. The one open field is the request's `params`, and it is fed
through an allowlist of client-authored keys: allowlisted values are
recorded verbatim (strings truncated at 1024 characters), and every other
parameter — `comment`, `summary`, `description`, `url`, `whiteboard`,
`custom_fields`, attachment `data` — is recorded as `{"_len": N}`, its
presence and size but never its content.

```json
{"v":1,"ts":"2026-02-03T04:05:06.789Z","seq":7,"session":{"id":"sess-1","transport":"http","remote":"192.0.2.7:52611"},"event":"tool_call","client":{"name":"example-agent","version":"1.4.2"},"request":{"tool":"bugs_quicksearch","id":"3","params":{"limit":50,"offset":0,"query":"kernel panic","status":"ALL"}},"guard":{"verdict":"served_filtered","policy_hash":"sha256:58013baa090cf77630373ab50cc5eaf2d679ec5a06e8a336600fc89b23bb8604","suppressed_count":2,"suppressed_ids":[1290040,1290041],"redacted_fields":[],"scan":{"scanned":50,"dropped":2}},"outcome":{"class":"ok","duration_ms":52}}
```

A reader of the file should skip empty lines and tolerate at most one
unparsable line per outage: a failed write can leave a partial line, and the
stream heals itself on the next successful record.

## Tool reference

Two rules cut across the tools that name bugs. A single call may reference at
most **25 distinct bug ids** — `bug_info`'s list, and for `update_bug_fields`
and `update_bug_dependencies` the bug being changed plus the local bugs its
see-also or dependency edits point at (a see-also entry on another tracker is
neither counted nor classified, since this policy has nothing to say about
it). And a tool that reaches a second bug (`mark_as_duplicate`,
`update_bug_fields`, `update_bug_dependencies`) requires at least `summary`
on that second bug, so an edit cannot confirm the existence of a bug the
policy hides.

`bug_url` and `mcp_server_info` answer from local state, and
`quicksearch_syntax` fetches a page Bugzilla serves without credentials;
none of the three needs an API key. Every other tool does, including
`bugzilla_server_info`, which requires no capability but still authenticates.

| Tool | What it does | Required capability |
|------|--------------|---------------------|
| `bug_info` | Details for up to 25 bug ids. Per id: full details with `read`, redacted summary with `summary`, otherwise a uniform "not accessible" entry | `read` / `summary` |
| `bug_history` | Change history of a bug, optionally only entries newer than a timestamp | `history` |
| `bug_comments` | Comments on a bug; private comments only per the private-comment gate | `comments` |
| `bugs_quicksearch` | Bugzilla [quicksearch](https://bugzilla.readthedocs.io/en/latest/using/finding.html#quicksearch) — the `status` filter (default `ALL`) is prefixed to the query, and under any non-empty status a number in the query is content-matched, so it also matches bugs that merely mention it; with an empty `status` the query goes to Bugzilla bare, where a query of nothing but numbers is an exact id lookup (use `bug_info` for an exact set of known ids; an all-ids query gets an advisory note saying so). Paginated by `limit` (default 50) and `offset` (default 0) over the bugs the client may see. Results are silently policy-filtered (denied dropped, summary-only redacted) | per result: `read` / `summary` |
| `summarize_bug` | Returns a summarization prompt built from the bug's public comments. Private comments are excluded unconditionally — this tool has no opt-in | `comments` |
| `list_attachments` | Attachment metadata (never attachment content) | `attachments` |
| `download_attachment` | Content of one attachment, alongside a JSON summary of its metadata: raster images (PNG, JPEG, GIF, WebP, BMP) as image content, everything else as a base64 blob resource under `bugzilla://attachment/{id}`. Capped by `max_attachment_bytes`; private attachments need the private-content double opt-in and, on download, a *missing* privacy flag counts as private | `attachments` on the owning bug |
| `add_comment` | Add a comment to a bug, optionally private | `comment` |
| `update_bug_status` | Change status and, optionally, resolution — both instance-defined; use `bug_fields` to discover them. Bugzilla requires a resolution when the target status is closing and the bug has none, and clears any resolution itself when the target status is open | `status` |
| `assign_bug` | Set the assignee | `assign` |
| `update_bug_fields` | Update priority/severity/resolution, summary, URL, whiteboard, version, target milestone, keywords and see-also links (both add/remove, never replace-all), and `cf_*` custom fields | `fields` on the bug **and** at least `summary` on every see-also target on this instance |
| `update_bug_dependencies` | Add/remove blocks and depends_on entries | `deps` |
| `add_cc_to_bug` | Add an email to the CC list (the tool only adds; removal is not exposed) | `cc` |
| `mark_as_duplicate` | Mark a bug as DUPLICATE of another, with an auto-generated comment when none is given; Bugzilla applies its configured duplicate status | `status` on the bug **and** at least `summary` on the duplicate target |
| `create_bug` | File a new bug, including `cf_*` custom fields; the request is policy-checked *as described* before anything is created. A policy refusal and a Bugzilla-side failure return the same refusal text at the same cost, so a failed create never says which of the two refused, or why | `create` on the bug as requested |
| `add_attachment` | Upload a base64-encoded attachment to a bug, optionally private or flagged as a patch, capped by `max_attachment_bytes` (decoded size) | `attach` on the target bug |
| `bug_url` | Compute `{server}/show_bug.cgi?id={id}` locally | none (contacts nothing) |
| `bugzilla_server_info` | Bugzilla version, extensions, timezone, time, parameters | none |
| `bugzilla_products` | *(needs `global.allow_discovery = true`)* Lists enterable product names, or fetches components/versions/milestones for up to 5 named products — as Bugzilla reports it to this server's key, never filtered by this policy | none |
| `bug_fields` | *(needs `global.allow_discovery = true`)* Lists bug fields (without legal values), or fetches up to 5 named fields with their legal values — each carrying `is_open` and `can_change_to` when Bugzilla reports them (only `bug_status` does), so a client can learn the workflow instead of guessing it — as Bugzilla reports it to this server's key, never filtered by this policy | none |
| `quicksearch_syntax` | Bugzilla's quicksearch syntax documentation (HTML) | none |
| `mcp_server_info` | This server's name and version, the Bugzilla URL, the transport, and a coarse policy summary: rule count, default action, `min_bug_age_days`, read-only flag, disabled tool names. Never a rule name or a match criterion | none |

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
