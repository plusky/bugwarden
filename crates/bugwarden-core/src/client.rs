//! Async Bugzilla REST client.
//!
//! The API key is passed per request instead of being
//! stored on the client, and it must never appear in logs, error messages,
//! or tool results (security invariant I12). Because the key may travel as
//! a URL query parameter (`api_key=...`), every [`reqwest::Error`] is
//! sanitized with [`reqwest::Error::without_url`] before it is wrapped, and
//! request logging records only the HTTP method and path — never the query
//! string.
//!
//! The `User-Agent` every request carries is supplied by the caller and
//! never derived here: this is a library, so a value built from its own
//! `CARGO_PKG_*` would name `bugwarden-core` in the access log of every
//! binary that embeds it (issue #55).

use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, Utc};
use serde_json::Value;

/// Fields fetched for guard classification of a bug.
pub const CLASSIFY_FIELDS: &str =
    "id,summary,product,component,status,resolution,severity,priority,keywords,groups,whiteboard,creation_time,last_change_time,creator";

/// Bugzilla `new_since` timestamp format (UTC, second precision, `Z`
/// suffix).
const TIMESTAMP_FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";

/// Async client for the Bugzilla REST API.
///
/// Built once at startup; the underlying [`reqwest::Client`] carries a 30
/// second timeout and the caller's `User-Agent`, and is reused for every
/// request. Authentication is applied per request: `Authorization: Bearer
/// {key}` when `use_auth_header` is set, otherwise an `api_key` query
/// parameter.
#[derive(Debug, Clone)]
pub struct BugzillaClient {
    /// Server base URL with any trailing `/` trimmed.
    base_url: String,
    /// REST endpoint root: `{base_url}/rest`.
    api_url: String,
    http: reqwest::Client,
    use_auth_header: bool,
}

impl BugzillaClient {
    /// Create a client for the Bugzilla instance at `base_url` (trailing
    /// slashes are trimmed), sending `user_agent` with every request.
    ///
    /// `user_agent` must name the *program* making the request, and is
    /// deliberately a parameter rather than a constant of this crate: a
    /// value built here from `CARGO_PKG_NAME`/`CARGO_PKG_VERSION` would
    /// name `bugwarden-core` in the access log of every binary that embeds
    /// it, which is both wrong and entirely plausible-looking (issue #55).
    /// Bugzilla's operator reads the value, so it belongs to the program's
    /// public identity — a name and version, never the API key, the policy
    /// path, or anything else about the deployment. That is the discipline
    /// of I12 applied to a surface I12 does not itself name (it governs
    /// logs, error messages and tool results).
    ///
    /// # Errors
    ///
    /// Returns an error when `user_agent` is blank — an anonymous client is
    /// what this parameter exists to prevent, so it fails at startup rather
    /// than sending an empty header — when it is not a valid HTTP header
    /// value, or when the underlying HTTP client cannot be built.
    pub fn new(base_url: &str, use_auth_header: bool, user_agent: &str) -> Result<Self> {
        if user_agent.trim().is_empty() {
            bail!("bugzilla client: user_agent must name the calling program, and was blank");
        }
        let base_url = base_url.trim_end_matches('/').to_string();
        let api_url = format!("{base_url}/rest");
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(user_agent)
            .build()
            .map_err(sanitize)?;
        Ok(Self {
            base_url,
            api_url,
            http,
            use_auth_header,
        })
    }

    /// The server base URL (no trailing slash).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// GET `/rest/version` — returns the server version string.
    pub async fn version(&self, key: &str) -> Result<String> {
        let v = self.get_json(key, "/version", &[]).await?;
        v.get("version")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("bugzilla /version response is missing the \"version\" field"))
    }

    /// GET `/rest/whoami` — the login name of the account the API key
    /// authenticates (the response's `name` field).
    ///
    /// A missing, non-string, or blank (empty or all-whitespace) `name` is
    /// a failure, not a login: a blank identity never resolves, so a
    /// degenerate empty caller can never compare equal to a blank `creator`
    /// field and grant on no evidence — resolution fails closed instead
    /// (I4). Authentication and error sanitization are identical to every
    /// other call: the key never appears in any error this returns (I12).
    pub async fn whoami(&self, key: &str) -> Result<String> {
        let v = self.get_json(key, "/whoami", &[]).await?;
        v.get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.trim().is_empty())
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("bugzilla /whoami response carries no usable \"name\" field"))
    }

    /// GET `/rest/valid_login?login=<login>` — whether the API key
    /// authenticates as exactly `login` (Bugzilla `Bugzilla->login`
    /// compares with Perl `eq`, i.e. case-sensitively).
    ///
    /// This is a portable identity *verifier*, not a discoverer: unlike
    /// `whoami` (a fork/BMO extension), `valid_login` is documented in the
    /// current Bugzilla Core v1 REST reference, so it works against a
    /// stock deployment. It answers exactly one question — "does this key
    /// authenticate as this login" — never "who does this key
    /// authenticate as".
    ///
    /// Bugzilla's REST layer normally wraps a scalar result as
    /// `{"result": true}`; a bare `true`/`false` body is accepted too. Any
    /// other shape (an object without a boolean `result`, a string, a
    /// number, `null`, …) is an error, never read as `false` — a response
    /// shape neither of those forms silently reading as "not this account"
    /// would be a fail-open surface hiding behind a fail-closed name.
    /// Authentication and error sanitization are identical to every other
    /// call: the key never appears in any error this returns (I12).
    pub async fn valid_login(&self, key: &str, login: &str) -> Result<bool> {
        let v = self
            .get_json(key, "/valid_login", &[("login", login.to_string())])
            .await?;
        match &v {
            Value::Bool(b) => Ok(*b),
            Value::Object(_) => v.get("result").and_then(Value::as_bool).ok_or_else(|| {
                anyhow!("bugzilla /valid_login response carries no usable boolean \"result\" field")
            }),
            _ => bail!(
                "bugzilla /valid_login response is neither a boolean nor an object with a \
                 boolean \"result\" field"
            ),
        }
    }

    /// Sequential GET of `/rest/version`, `/rest/extensions`, `/rest/time`
    /// and `/rest/parameters`, combined into
    /// `{url, version, extensions, timezone, time, parameters}`.
    ///
    /// The endpoints are fetched one at a time — some Bugzilla deployments
    /// drop connections when a single client opens several at once — and a
    /// failing endpoint degrades only its own fields, with the sanitized
    /// reason collected under `"unavailable"`. The call errors only when
    /// every endpoint fails.
    pub async fn server_info(&self, key: &str) -> Result<Value> {
        let mut unavailable: Vec<String> = Vec::new();
        let version = self.info_endpoint(key, "/version", &mut unavailable).await;
        let extensions = self
            .info_endpoint(key, "/extensions", &mut unavailable)
            .await;
        let time = self.info_endpoint(key, "/time", &mut unavailable).await;
        let parameters = self
            .info_endpoint(key, "/parameters", &mut unavailable)
            .await;
        if version.is_none() && extensions.is_none() && time.is_none() && parameters.is_none() {
            bail!(
                "all bugzilla server-info endpoints failed: {}",
                unavailable.join("; ")
            );
        }
        let mut info = serde_json::json!({
            "url": self.base_url,
            "version": version
                .as_ref()
                .and_then(|v| v.get("version"))
                .cloned()
                .unwrap_or(Value::Null),
            "extensions": extensions
                .as_ref()
                .and_then(|v| v.get("extensions"))
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
            "timezone": time
                .as_ref()
                .and_then(|v| v.get("tz_name"))
                .cloned()
                .unwrap_or(Value::Null),
            "time": time
                .as_ref()
                .and_then(|v| v.get("web_time"))
                .cloned()
                .unwrap_or(Value::Null),
            "parameters": parameters
                .as_ref()
                .and_then(|v| v.get("parameters"))
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
        });
        if !unavailable.is_empty() {
            info["unavailable"] = serde_json::json!(unavailable);
        }
        Ok(info)
    }

    /// GET one server-info endpoint, degrading a failure into `None` and
    /// recording the sanitized reason.
    async fn info_endpoint(
        &self,
        key: &str,
        path: &'static str,
        unavailable: &mut Vec<String>,
    ) -> Option<Value> {
        match self.get_json(key, path, &[]).await {
            Ok(v) => Some(v),
            Err(e) => {
                unavailable.push(format!("{path}: {e:#}"));
                None
            }
        }
    }

    /// GET `/rest/bug?id=1,2,3[&include_fields=..]` — returns the whole
    /// response envelope.
    pub async fn get_bugs(
        &self,
        key: &str,
        ids: &[u64],
        include_fields: Option<&str>,
    ) -> Result<Value> {
        let id_list = ids
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let mut query = vec![("id", id_list)];
        if let Some(fields) = include_fields {
            query.push(("include_fields", fields.to_string()));
        }
        self.get_json(key, "/bug", &query).await
    }

    /// GET `/rest/bug/{id}/history[?new_since=..]` — returns the
    /// `bugs[0].history` array (empty array when absent).
    pub async fn bug_history(
        &self,
        key: &str,
        id: u64,
        new_since: Option<DateTime<Utc>>,
    ) -> Result<Value> {
        let path = format!("/bug/{id}/history");
        let mut query: Vec<(&str, String)> = Vec::new();
        if let Some(ts) = new_since {
            query.push(("new_since", ts.format(TIMESTAMP_FORMAT).to_string()));
        }
        let v = self.get_json(key, &path, &query).await?;
        Ok(v.get("bugs")
            .and_then(Value::as_array)
            .and_then(|bugs| bugs.first())
            .and_then(|bug| bug.get("history"))
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new())))
    }

    /// GET `/rest/bug/{id}/comment[?new_since=..]` — returns the
    /// `bugs.{id}.comments` array (empty when absent). The envelope shape is
    /// `{"bugs": {"<id>": {"comments": [...]}}}`.
    pub async fn bug_comments(
        &self,
        key: &str,
        id: u64,
        new_since: Option<DateTime<Utc>>,
    ) -> Result<Vec<Value>> {
        let path = format!("/bug/{id}/comment");
        let mut query: Vec<(&str, String)> = Vec::new();
        if let Some(ts) = new_since {
            query.push(("new_since", ts.format(TIMESTAMP_FORMAT).to_string()));
        }
        let v = self.get_json(key, &path, &query).await?;
        let id_key = id.to_string();
        Ok(v.get("bugs")
            .and_then(|bugs| bugs.get(id_key.as_str()))
            .and_then(|bug| bug.get("comments"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    /// POST `/rest/bug/{id}/comment` with `{"comment": .., "is_private": ..}`
    /// — returns the response envelope.
    pub async fn add_comment(
        &self,
        key: &str,
        id: u64,
        comment: &str,
        is_private: bool,
    ) -> Result<Value> {
        let path = format!("/bug/{id}/comment");
        let payload = serde_json::json!({ "comment": comment, "is_private": is_private });
        self.send_json_body(reqwest::Method::POST, key, &path, &payload)
            .await
    }

    /// GET `/rest/bug?quicksearch=..` — returns the whole response envelope.
    ///
    /// The quicksearch expression is `"{status} {query}"` when `status` is
    /// non-empty, otherwise just `query`; results are ordered by relevance.
    pub async fn quicksearch(
        &self,
        key: &str,
        query: &str,
        status: &str,
        include_fields: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Value> {
        let quicksearch = if status.is_empty() {
            query.to_string()
        } else {
            format!("{status} {query}")
        };
        let params: Vec<(&str, String)> = vec![
            ("quicksearch", quicksearch),
            ("include_fields", include_fields.to_string()),
            ("limit", limit.to_string()),
            ("offset", offset.to_string()),
            ("order", "relevance".to_string()),
        ];
        self.get_json(key, "/bug", &params).await
    }

    /// POST `/rest/bug` — file a new bug, returning the response envelope
    /// (`{"id": N}` on success).
    pub async fn create_bug(&self, key: &str, payload: Value) -> Result<Value> {
        self.send_json_body(reqwest::Method::POST, key, "/bug", &payload)
            .await
    }

    /// POST `/rest/bug/{id}/attachment` — upload an attachment, returning the
    /// response envelope (`{"ids": [N]}` on success).
    pub async fn add_attachment(&self, key: &str, id: u64, payload: Value) -> Result<Value> {
        let path = format!("/bug/{id}/attachment");
        self.send_json_body(reqwest::Method::POST, key, &path, &payload)
            .await
    }

    /// PUT `/rest/bug/{id}` with a caller-built payload (the caller adds
    /// `"comment": {"body": ..}` when a comment is wanted) — returns the
    /// response envelope.
    pub async fn update_bug(&self, key: &str, id: u64, payload: Value) -> Result<Value> {
        let path = format!("/bug/{id}");
        self.send_json_body(reqwest::Method::PUT, key, &path, &payload)
            .await
    }

    /// GET `/rest/bug/{id}/attachment?exclude_fields=data` — returns the
    /// `bugs.{id}` attachment metadata array (empty when absent). Attachment
    /// payloads are never fetched.
    pub async fn attachments(&self, key: &str, id: u64) -> Result<Value> {
        let path = format!("/bug/{id}/attachment");
        let v = self
            .get_json(key, &path, &[("exclude_fields", "data".to_string())])
            .await?;
        let id_key = id.to_string();
        Ok(v.get("bugs")
            .and_then(|bugs| bugs.get(id_key.as_str()))
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new())))
    }

    /// GET `/rest/bug/attachment/{attachment_id}?exclude_fields=data` — the
    /// metadata of one attachment, without its content. Returns `None` when
    /// the response carries no entry for the id.
    pub async fn attachment_meta(&self, key: &str, attachment_id: u64) -> Result<Option<Value>> {
        self.attachment_envelope(
            key,
            attachment_id,
            &[("exclude_fields", "data".to_string())],
        )
        .await
    }

    /// GET `/rest/bug/attachment/{attachment_id}` — one attachment including
    /// its base64 `data` field. Returns `None` when the response carries no
    /// entry for the id.
    ///
    /// Callers must run the guard's attachment gate on the metadata BEFORE
    /// calling this (I8): the blob is the sensitive payload.
    pub async fn attachment_data(&self, key: &str, attachment_id: u64) -> Result<Option<Value>> {
        self.attachment_envelope(key, attachment_id, &[]).await
    }

    async fn attachment_envelope(
        &self,
        key: &str,
        attachment_id: u64,
        query: &[(&str, String)],
    ) -> Result<Option<Value>> {
        let path = format!("/bug/attachment/{attachment_id}");
        let v = self.get_json(key, &path, query).await?;
        let id_key = attachment_id.to_string();
        Ok(v.get("attachments")
            .and_then(|atts| atts.get(id_key.as_str()))
            .cloned()
            .filter(|att| !att.is_null()))
    }

    /// GET `{base_url}/page.cgi?id=quicksearch.html` — the quicksearch
    /// syntax documentation page. This is a plain HTML page, not a REST
    /// endpoint, and needs no authentication: no API key is attached.
    pub async fn quicksearch_syntax_html(&self) -> Result<String> {
        let rb = self
            .http
            .get(format!("{}/page.cgi", self.base_url))
            .header(reqwest::header::ACCEPT, "application/json")
            .query(&[("id", "quicksearch.html")]);
        let (status, body) = self.send(rb, "GET", "/page.cgi").await?;
        let parsed: Option<Value> = serde_json::from_str(&body).ok();
        check_error(status, parsed.as_ref())?;
        Ok(body)
    }

    /// Attach per-request authentication: `Authorization: Bearer {key}` when
    /// `use_auth_header`, else an `api_key` query parameter.
    fn apply_auth(&self, rb: reqwest::RequestBuilder, key: &str) -> reqwest::RequestBuilder {
        if self.use_auth_header {
            rb.header(reqwest::header::AUTHORIZATION, format!("Bearer {key}"))
        } else {
            rb.query(&[("api_key", key)])
        }
    }

    /// Send a prepared request, returning `(status, body)`. Logs method and
    /// path only (no query string — I12) and sanitizes transport errors.
    async fn send(
        &self,
        rb: reqwest::RequestBuilder,
        method: &str,
        path: &str,
    ) -> Result<(reqwest::StatusCode, String)> {
        tracing::debug!(method, path, "bugzilla request");
        let resp = rb.send().await.map_err(sanitize)?;
        let status = resp.status();
        let body = resp.text().await.map_err(sanitize)?;
        Ok((status, body))
    }

    /// Authenticated GET of a REST path (relative to `{base_url}/rest`)
    /// returning the parsed JSON body.
    async fn get_json(&self, key: &str, path: &str, query: &[(&str, String)]) -> Result<Value> {
        let mut rb = self
            .http
            .get(format!("{}{}", self.api_url, path))
            .header(reqwest::header::ACCEPT, "application/json");
        if !query.is_empty() {
            rb = rb.query(query);
        }
        let rb = self.apply_auth(rb, key);
        let (status, body) = self.send(rb, "GET", path).await?;
        parse_response(status, &body)
    }

    /// Authenticated POST/PUT of a JSON payload to a REST path, returning
    /// the parsed JSON body.
    async fn send_json_body(
        &self,
        method: reqwest::Method,
        key: &str,
        path: &str,
        payload: &Value,
    ) -> Result<Value> {
        let method_name = method.as_str().to_string();
        let rb = self
            .http
            .request(method, format!("{}{}", self.api_url, path))
            .header(reqwest::header::ACCEPT, "application/json")
            .json(payload);
        let rb = self.apply_auth(rb, key);
        let (status, body) = self.send(rb, &method_name, path).await?;
        parse_response(status, &body)
    }
}

/// Wrap a [`reqwest::Error`] with its URL stripped. The URL may contain the
/// API key as a query parameter, so it must never reach an error message or
/// log line (I12).
fn sanitize(e: reqwest::Error) -> anyhow::Error {
    anyhow::Error::new(e.without_url())
}

/// Fail on HTTP-level errors: a non-2xx status, or a Bugzilla error body
/// (`{"error": true, ...}`) even under a 200 status. The error text carries
/// the HTTP status and the Bugzilla `message` field when present — never the
/// request URL.
fn check_error(status: reqwest::StatusCode, parsed: Option<&Value>) -> Result<()> {
    let bz_error = parsed
        .and_then(|v| v.get("error"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !status.is_success() || bz_error {
        let message = parsed
            .and_then(|v| v.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("unknown error");
        bail!("bugzilla error (HTTP {}): {}", status.as_u16(), message);
    }
    Ok(())
}

/// [`check_error`], then require a JSON body.
fn parse_response(status: reqwest::StatusCode, body: &str) -> Result<Value> {
    let parsed: Option<Value> = serde_json::from_str(body).ok();
    check_error(status, parsed.as_ref())?;
    parsed.ok_or_else(|| {
        anyhow!(
            "bugzilla error (HTTP {}): response body is not valid JSON",
            status.as_u16()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use reqwest::StatusCode;

    /// Stands in for a real program's identity, naming neither this crate
    /// nor the binary that ships it; the point of the parameter is that
    /// this crate never picks one (#55).
    const UA: &str = "probe-agent/0.0.0";

    #[test]
    fn new_trims_trailing_slashes() {
        let c = BugzillaClient::new("https://bugzilla.example.com/", false, UA).unwrap();
        assert_eq!(c.base_url(), "https://bugzilla.example.com");
        assert_eq!(c.api_url, "https://bugzilla.example.com/rest");

        let c = BugzillaClient::new("https://bugzilla.example.com///", true, UA).unwrap();
        assert_eq!(c.base_url(), "https://bugzilla.example.com");

        let c = BugzillaClient::new("https://bugzilla.example.com", false, UA).unwrap();
        assert_eq!(c.base_url(), "https://bugzilla.example.com");
    }

    #[test]
    fn new_refuses_to_build_an_anonymous_client() {
        // A blank identity is the state #55 exists to end, so it fails at
        // startup rather than sending an empty header to Bugzilla.
        for blank in ["", " ", "\t\n "] {
            let e = BugzillaClient::new("https://bugzilla.example.com", false, blank)
                .expect_err("a blank user agent must not build a client");
            assert!(
                e.to_string().contains("user_agent"),
                "the error must name what is missing: {e:#}"
            );
        }
    }

    #[test]
    fn new_refuses_a_user_agent_that_is_not_a_header_value() {
        // reqwest defers this to build(); it must surface as an error and
        // not a panic, since the value crosses a public API boundary.
        let e = BugzillaClient::new("https://bugzilla.example.com", false, "bad\nagent/1.0")
            .expect_err("a user agent with a newline must not build a client");
        // And it must be reqwest's refusal, not the blank-identity bail
        // widened until it swallows this case too.
        assert!(
            !e.to_string().contains("blank"),
            "a malformed identity is not a missing one: {e:#}"
        );
    }

    #[test]
    fn timestamp_format_renders_utc_z() {
        let ts = Utc.with_ymd_and_hms(2024, 1, 2, 3, 4, 5).unwrap();
        assert_eq!(
            ts.format(TIMESTAMP_FORMAT).to_string(),
            "2024-01-02T03:04:05Z"
        );
    }

    #[test]
    fn parse_response_ok_on_success_json() {
        let v = parse_response(StatusCode::OK, r#"{"bugs": []}"#).unwrap();
        assert_eq!(v, serde_json::json!({ "bugs": [] }));
    }

    #[test]
    fn parse_response_uses_bugzilla_message_on_http_error() {
        let err = parse_response(
            StatusCode::UNAUTHORIZED,
            r#"{"error": true, "code": 306, "message": "invalid credentials"}"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "bugzilla error (HTTP 401): invalid credentials"
        );
    }

    #[test]
    fn parse_response_unknown_error_when_body_not_json() {
        let err = parse_response(StatusCode::BAD_GATEWAY, "<html>gateway</html>").unwrap_err();
        assert_eq!(err.to_string(), "bugzilla error (HTTP 502): unknown error");
    }

    #[test]
    fn parse_response_detects_error_body_under_200() {
        let err = parse_response(
            StatusCode::OK,
            r#"{"error": true, "message": "Bug 1 does not exist."}"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "bugzilla error (HTTP 200): Bug 1 does not exist."
        );
    }

    #[test]
    fn parse_response_rejects_non_json_success_body() {
        let err = parse_response(StatusCode::OK, "not json").unwrap_err();
        assert_eq!(
            err.to_string(),
            "bugzilla error (HTTP 200): response body is not valid JSON"
        );
    }
}
