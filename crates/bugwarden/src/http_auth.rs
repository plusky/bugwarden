//! Who the HTTP caller is, decided before rmcp sees the request (issue #32).
//!
//! Key custody (`config.rs`) answers who authenticates to Bugzilla. This
//! answers the other direction: who is allowed to ask bugwarden anything at
//! all. It matters only over http. A stdio client already owns the process it
//! spawned, so the operating system decided the question; an http listener
//! decides nothing until something here does, and under server-held key
//! custody "nothing" means handing the deployment's Bugzilla credential to
//! whoever opened the socket first.
//!
//! Two secrets, two answers. One grants the deployment's whole tool surface,
//! the other only the tools that read. Both arrive as `Authorization: Bearer`,
//! both are matched without branching on the result, and everything that does
//! not match gets one response with nothing in it.
//!
//! The secrets are taken from the environment and from nowhere else. A
//! command-line option would publish them through `ps` to every account on the
//! host, so no option exists — which also means no token can reach a `{:?}` of
//! [`crate::config::Cli`], because none is stored there. Nothing in this
//! module derives `Debug` over a secret either (I12).
//!
//! The two variable names, the length floor and the refusal shape are chosen
//! to match the sibling `ruoqa-mcp` deployment so one fleet configuration
//! serves both. That is a statement about the interface, not about the
//! implementation below.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::header::{HeaderValue, AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use rmcp::service::RequestContext;
use rmcp::RoleServer;
use subtle::ConstantTimeEq as _;

use crate::config::Transport;

/// Environment variable carrying the secret that grants the write scope.
pub const WRITE_TOKEN_VAR: &str = "BUGWARDEN_HTTP_TOKEN";

/// Environment variable carrying the secret that grants the read scope.
pub const READ_TOKEN_VAR: &str = "BUGWARDEN_HTTP_READ_TOKEN";

/// Fewest characters a usable token may have.
///
/// Thirty-two is not a cryptographic threshold; it is the line below which a
/// value stops looking generated. `openssl rand -hex 32` lands at 64, twice
/// over, while anything a person typed from memory falls short — and that is
/// the mistake worth refusing at startup rather than discovering from an
/// access log.
const MIN_TOKEN_LEN: usize = 32;

/// The two answers a credential can earn.
///
/// Ordered on purpose, least first: [`HttpAuth::scope_for`] takes the maximum
/// over everything that matched instead of stopping at the first hit.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Scope {
    /// Only the tools that read — everything outside
    /// [`crate::server::WRITE_TOOLS`].
    Read,
    /// Whatever this deployment's guard policy still serves after pruning.
    Write,
}

/// Which credentials a running listener holds, for the startup log.
///
/// Says how the door is locked and never what the key is, so it is safe to
/// print (I12).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthMode {
    /// `--insecure-no-auth`: the door is open.
    Insecure,
    /// One secret, granting the write scope.
    Write,
    /// One secret, granting the read scope.
    Read,
    /// Both secrets, and therefore both scopes.
    WriteAndRead,
}

impl fmt::Display for AuthMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Insecure => "disabled",
            Self::Write => "bearer, write scope only",
            Self::Read => "bearer, read scope only",
            Self::WriteAndRead => "bearer, write and read scopes",
        })
    }
}

/// What the two variables held when the process started.
///
/// A plain struct rather than a direct read of `std::env`, so resolution is a
/// function of its argument and every test states its own world instead of
/// mutating the process. No `Debug`: both fields are secret (I12).
#[derive(Default, Clone)]
pub struct HttpEnv {
    /// [`WRITE_TOKEN_VAR`], if it held anything.
    pub write: Option<String>,
    /// [`READ_TOKEN_VAR`], if it held anything.
    pub read: Option<String>,
}

impl HttpEnv {
    /// Read both variables out of the process environment.
    ///
    /// A variable set to the empty string counts as one that was never set.
    /// Unit files and container specs clear a variable by emptying it, and
    /// `--api-key-file` already reads `=` that way; here the convention has
    /// teeth, because "cleared" must land on the startup refusal rather than
    /// on an open port.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            write: env_token(WRITE_TOKEN_VAR),
            read: env_token(READ_TOKEN_VAR),
        }
    }

    /// Whether the process was started with no token at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.write.is_none() && self.read.is_none()
    }
}

/// One environment variable, with the empty string read as absence.
fn env_token(var: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(value) if !value.is_empty() => Some(value),
        _ => None,
    }
}

/// What is wrong with a token the operator configured.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TokenFlaw {
    /// Under [`MIN_TOKEN_LEN`] characters.
    TooShort,
    /// Holds a byte that cannot ride in an `Authorization` header, or a
    /// space, which usually means a value was pasted with something attached.
    NotBearerSafe,
}

/// Why this process must not open an http listener.
///
/// Every one of these is fatal and reported before a socket exists. There is
/// no degraded mode: a deployment that half-configured its credentials is a
/// deployment whose operator believes it is protected.
///
/// The messages name variables, never their contents (I12).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AuthConfigError {
    /// No token, and no one said to serve without one.
    MissingCredential,
    /// A token and `--insecure-no-auth` together: the operator asked for two
    /// incompatible things and neither can be assumed to be the real intent.
    ContradictoryOptOut,
    /// A configured token could not be used as a bearer credential.
    UnusableToken {
        /// The variable it came from.
        var: &'static str,
        /// What disqualified it.
        flaw: TokenFlaw,
    },
    /// One string in both variables, which would make the scopes a fiction.
    IndistinguishableScopes,
}

impl fmt::Display for AuthConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCredential => write!(
                f,
                "--transport http requires a bearer token: put one in {WRITE_TOKEN_VAR} for \
                 the write scope or {READ_TOKEN_VAR} for the read scope, or pass \
                 --insecure-no-auth to serve the endpoint to anyone who reaches it"
            ),
            Self::ContradictoryOptOut => write!(
                f,
                "--insecure-no-auth conflicts with a configured bearer token \
                 ({WRITE_TOKEN_VAR} / {READ_TOKEN_VAR}); keep one of the two"
            ),
            Self::UnusableToken {
                var,
                flaw: TokenFlaw::TooShort,
            } => write!(
                f,
                "{var} holds fewer than {MIN_TOKEN_LEN} characters; generate one with \
                 `openssl rand -hex 32`"
            ),
            Self::UnusableToken {
                var,
                flaw: TokenFlaw::NotBearerSafe,
            } => write!(
                f,
                "{var} holds a character a bearer credential cannot carry; use printable \
                 ASCII, and no spaces"
            ),
            Self::IndistinguishableScopes => write!(
                f,
                "{WRITE_TOKEN_VAR} and {READ_TOKEN_VAR} hold identical values, which would \
                 make the two scopes indistinguishable"
            ),
        }
    }
}

impl std::error::Error for AuthConfigError {}

/// A secret that passed startup validation.
///
/// Wrapping the `String` is what keeps the two operations that may touch a
/// token — checking it at startup, matching it per request — in one place, so
/// neither can be done some other way somewhere else. No `Debug`, no
/// accessor: nothing can read the bytes back out.
struct Token(String);

impl Token {
    /// Accept `raw` as a usable bearer credential, or say why not.
    ///
    /// Two things disqualify it. A byte outside printable ASCII cannot be put
    /// in a header at all, and a space would split the credential from its
    /// scheme on the wire — both are almost always a paste that picked up a
    /// newline or a quote. Length comes second, because "it is not a token"
    /// is a better diagnosis than "it is a short token".
    fn parse(var: &'static str, raw: &str) -> Result<Self, AuthConfigError> {
        let flawed = |flaw| AuthConfigError::UnusableToken { var, flaw };
        if !raw.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(flawed(TokenFlaw::NotBearerSafe));
        }
        if raw.len() < MIN_TOKEN_LEN {
            return Err(flawed(TokenFlaw::TooShort));
        }
        Ok(Self(raw.to_owned()))
    }

    /// Whether `candidate` is this token, compared in constant time.
    ///
    /// `subtle` and not `==`: the two agree on every answer and disagree on
    /// how long they take to give it, and the second is what a caller
    /// guessing a token measures.
    fn verifies(&self, candidate: &str) -> bool {
        self.0.as_bytes().ct_eq(candidate.as_bytes()).into()
    }

    /// Whether two configured tokens are the same string. Not constant time,
    /// and it does not need to be: both operands are the operator's own, this
    /// runs once at startup, and no caller is watching.
    fn is(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

/// The credentials a listener checks against, and the counter for the ones it
/// turns away.
///
/// No `Debug` impl: it holds secrets, the same reason
/// [`crate::config::KeyCustody`] has none.
pub struct HttpAuth {
    write: Option<Token>,
    read: Option<Token>,
    mode: AuthMode,
    refusals: AtomicU64,
}

impl HttpAuth {
    /// Decide what this listener will accept, or refuse to have one.
    ///
    /// Validation of each token comes first, so an operator who mistyped one
    /// is told which variable is at fault rather than being told the pair is
    /// unusable. What survives that is then read as an intent: two tokens,
    /// one token, or an explicit request to serve without any.
    ///
    /// # Errors
    ///
    /// [`AuthConfigError`], every variant of which is fatal.
    pub fn resolve(env: &HttpEnv, insecure: bool) -> Result<Self, AuthConfigError> {
        let write = env
            .write
            .as_deref()
            .map(|raw| Token::parse(WRITE_TOKEN_VAR, raw))
            .transpose()?;
        let read = env
            .read
            .as_deref()
            .map(|raw| Token::parse(READ_TOKEN_VAR, raw))
            .transpose()?;
        if let (Some(write), Some(read)) = (&write, &read) {
            if write.is(read) {
                return Err(AuthConfigError::IndistinguishableScopes);
            }
        }
        let mode = match (insecure, write.is_some(), read.is_some()) {
            (true, false, false) => AuthMode::Insecure,
            (true, _, _) => return Err(AuthConfigError::ContradictoryOptOut),
            (false, false, false) => return Err(AuthConfigError::MissingCredential),
            (false, true, true) => AuthMode::WriteAndRead,
            (false, true, false) => AuthMode::Write,
            (false, false, true) => AuthMode::Read,
        };
        Ok(Self {
            write,
            read,
            mode,
            refusals: AtomicU64::new(0),
        })
    }

    /// What this listener accepts.
    #[must_use]
    pub fn mode(&self) -> AuthMode {
        self.mode
    }

    /// Whether this listener checks nothing.
    #[must_use]
    pub fn is_insecure(&self) -> bool {
        self.mode == AuthMode::Insecure
    }

    /// Announce the mode at startup — the mode, and not one byte of a token
    /// (I12).
    ///
    /// An unauthenticated listener is a `warn!`, because a server with no
    /// door in front of a Bugzilla credential is not a routine arrangement
    /// and the operator should see it scroll past.
    pub fn log_startup_mode(&self) {
        match self.mode {
            AuthMode::Insecure => tracing::warn!(
                "--insecure-no-auth: the http endpoint is served WITHOUT authentication; \
                 every caller that can reach the port gets the full write scope"
            ),
            mode => tracing::info!("http authentication: {mode}"),
        }
    }

    /// Each configured credential and the scope it grants.
    fn credentials(&self) -> impl Iterator<Item = (Scope, &Token)> {
        [
            (Scope::Write, self.write.as_ref()),
            (Scope::Read, self.read.as_ref()),
        ]
        .into_iter()
        .filter_map(|(scope, token)| token.map(|token| (scope, token)))
    }

    /// What an `Authorization` header value earns, if anything.
    ///
    /// `None` covers every way of not being authorized — absent, wrong
    /// scheme, malformed, or simply a value nobody configured — because the
    /// caller learns the same thing from all of them.
    #[must_use]
    pub fn scope_for(&self, header: Option<&str>) -> Option<Scope> {
        let candidate = header.and_then(bearer_credential)?;
        // Folded over every credential rather than returned from the first
        // hit, and the maximum wins. Leaving early would let a caller time
        // the reply to learn WHICH of the two secrets a guess collided with,
        // which is a large step from knowing that it did not.
        self.credentials()
            .filter(|(_, token)| token.verifies(candidate))
            .fold(None, |best, (scope, _)| best.max(Some(scope)))
    }

    /// Count a refusal, and say so on the first and then at every doubling.
    ///
    /// The refusal happens above `call_tool`, where audit records are
    /// written, so no record can carry it (#32, constraint 5). A log line
    /// is what is left — and it has to stay cheap, because the people
    /// triggering it are by definition not authorized to make this process do
    /// work. Doubling bounds the output at the logarithm of the attempts. The
    /// line carries a count and nothing else: no token, no header, no path,
    /// no peer, so it answers no question a stranger might be asking.
    fn note_refusal(&self) {
        let total = self.refusals.fetch_add(1, Ordering::Relaxed) + 1;
        if total.is_power_of_two() {
            tracing::warn!(
                refused = total,
                "http bearer authentication refused a request"
            );
        }
    }
}

/// The credential out of an `Authorization` value, if it is a bearer one.
///
/// The scheme is matched case-insensitively (RFC 9110 says schemes are), the
/// credential is not. Exactly two whitespace-separated pieces are accepted: a
/// value with more is not a bearer credential with a suffix, it is something
/// this server does not understand, and guessing at it is how a parser starts
/// disagreeing with the proxy in front of it.
fn bearer_credential(header: &str) -> Option<&str> {
    let mut pieces = header.split_ascii_whitespace();
    let scheme = pieces.next()?;
    let credential = pieces.next()?;
    match (scheme.eq_ignore_ascii_case("bearer"), pieces.next()) {
        (true, None) => Some(credential),
        _ => None,
    }
}

/// The gate for `transport`, or `None` where there is nothing to gate.
///
/// stdio gets `None` and gets it unconditionally: the client launched this
/// process, no port is open, and there is no second party for a token to
/// distinguish. A token sitting in the environment of a stdio run is
/// therefore ignored outright rather than validated — an unusable value is
/// not an error for a transport that would not have used a usable one either.
/// `--insecure-no-auth` is inert there for the same reason.
///
/// # Errors
///
/// [`AuthConfigError`], for the http transport only.
pub fn resolve_for(
    transport: Transport,
    env: &HttpEnv,
    insecure: bool,
) -> Result<Option<HttpAuth>, AuthConfigError> {
    match transport {
        Transport::Http => HttpAuth::resolve(env, insecure).map(Some),
        Transport::Stdio => {
            if !env.is_empty() || insecure {
                tracing::debug!(
                    "http bearer settings are configured but the transport is stdio; ignoring"
                );
            }
            Ok(None)
        }
    }
}

/// Put `auth` in front of `router`.
///
/// The one place a guarded router is built, so `main` and every test that
/// serves one are looking at the same wiring; a test cannot pass against a
/// gate the deployment does not have.
///
/// It wraps the router rather than the `/mcp` route, and that is the point:
/// an unauthenticated request to a path this server does not serve is refused
/// exactly like one to a path it does, so probing recovers no map of the
/// surface (I2).
pub fn guard_router(router: axum::Router, auth: Arc<HttpAuth>) -> axum::Router {
    router.layer(axum::middleware::from_fn(move |request, next| {
        gate(Arc::clone(&auth), request, next)
    }))
}

/// Let an authorized request through carrying its scope; turn the rest away.
async fn gate(auth: Arc<HttpAuth>, mut request: Request, next: Next) -> Response {
    if auth.is_insecure() {
        return next.run(request).await;
    }
    match auth.scope_for(sole_authorization(&request)) {
        Some(scope) => {
            request.extensions_mut().insert(scope);
            next.run(request).await
        }
        None => {
            auth.note_refusal();
            unauthorized()
        }
    }
}

/// The request's `Authorization` value, when it has exactly one.
///
/// Two of them is not a request with a spare credential, it is a malformed
/// one (RFC 9110), and resolving it either way is worse than refusing: a
/// proxy on the path that forwards the last value while this read the first
/// would authorize a token the operator never saw. Absent and duplicated both
/// come back `None`, and both end at the same refusal.
fn sole_authorization(request: &Request) -> Option<&str> {
    let mut values = request.headers().get_all(AUTHORIZATION).iter();
    match (values.next(), values.next()) {
        (Some(only), None) => only.to_str().ok(),
        _ => None,
    }
}

/// The refusal: `401`, `WWW-Authenticate: Bearer`, nothing else.
///
/// One response for every way of failing, down to the byte. A caller who
/// cannot get in is told that and only that — not whether the header was
/// missing or wrong, and not whether the path they tried exists (I2).
fn unauthorized() -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

/// The scope [`gate`] attached to this request, as the MCP handler sees it.
///
/// `None` means no scope was attached, which happens over stdio, under
/// `--insecure-no-auth`, and — were the listener ever built without the gate
/// — on a request that skipped it. The caller decides what absence means;
/// `BugWarden` treats it as "reaches nothing".
#[must_use]
pub fn scope_of(context: &RequestContext<RoleServer>) -> Option<Scope> {
    let parts = context.extensions.get::<Parts>()?;
    parts.extensions.get::<Scope>().copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    const WRITE: &str = "0123456789abcdef0123456789abcdef";
    const READ: &str = "fedcba9876543210fedcba9876543210";

    fn env(write: Option<&str>, read: Option<&str>) -> HttpEnv {
        HttpEnv {
            write: write.map(ToOwned::to_owned),
            read: read.map(ToOwned::to_owned),
        }
    }

    fn unusable(var: &'static str, flaw: TokenFlaw) -> Option<AuthConfigError> {
        Some(AuthConfigError::UnusableToken { var, flaw })
    }

    #[test]
    fn http_without_any_token_refuses_to_start() {
        assert_eq!(
            HttpAuth::resolve(&HttpEnv::default(), false).err(),
            Some(AuthConfigError::MissingCredential)
        );
    }

    #[test]
    fn insecure_with_a_token_refuses_to_start() {
        for e in [env(Some(WRITE), None), env(None, Some(READ))] {
            assert_eq!(
                HttpAuth::resolve(&e, true).err(),
                Some(AuthConfigError::ContradictoryOptOut)
            );
        }
    }

    #[test]
    fn insecure_without_a_token_starts_with_authentication_off() {
        let auth = HttpAuth::resolve(&HttpEnv::default(), true).expect("resolve");
        assert!(auth.is_insecure());
        assert_eq!(auth.mode(), AuthMode::Insecure);
        assert_eq!(auth.scope_for(None), None);
    }

    #[test]
    fn short_or_unprintable_tokens_refuse_to_start() {
        // 31 characters: one under the floor, so the boundary itself is
        // pinned rather than some obviously tiny value.
        let just_short = &WRITE[..MIN_TOKEN_LEN - 1];
        assert_eq!(
            HttpAuth::resolve(&env(Some(just_short), None), false).err(),
            unusable(WRITE_TOKEN_VAR, TokenFlaw::TooShort)
        );
        assert!(HttpAuth::resolve(&env(Some(WRITE), None), false).is_ok());
        // The read variable is validated on its own terms, and named.
        assert_eq!(
            HttpAuth::resolve(&env(None, Some(just_short)), false).err(),
            unusable(READ_TOKEN_VAR, TokenFlaw::TooShort)
        );
        for bad in [
            "0123456789abcdef 0123456789abcdef",
            "0123456789abcdef\t0123456789abcdef",
            "0123456789abcdef\n0123456789abcdef",
            "0123456789abcdef\u{e9}123456789abcdef",
        ] {
            assert_eq!(
                HttpAuth::resolve(&env(Some(bad), None), false).err(),
                unusable(WRITE_TOKEN_VAR, TokenFlaw::NotBearerSafe),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn identical_tokens_refuse_to_start() {
        assert_eq!(
            HttpAuth::resolve(&env(Some(WRITE), Some(WRITE)), false).err(),
            Some(AuthConfigError::IndistinguishableScopes)
        );
    }

    #[test]
    fn either_token_may_be_set_alone() {
        assert_eq!(
            HttpAuth::resolve(&env(Some(WRITE), None), false)
                .expect("write alone")
                .mode(),
            AuthMode::Write
        );
        assert_eq!(
            HttpAuth::resolve(&env(None, Some(READ)), false)
                .expect("read alone")
                .mode(),
            AuthMode::Read
        );
        assert_eq!(
            HttpAuth::resolve(&env(Some(WRITE), Some(READ)), false)
                .expect("both")
                .mode(),
            AuthMode::WriteAndRead
        );
    }

    #[test]
    fn each_token_grants_exactly_its_own_scope() {
        let auth = HttpAuth::resolve(&env(Some(WRITE), Some(READ)), false).expect("resolve");
        assert_eq!(
            auth.scope_for(Some(&format!("Bearer {WRITE}"))),
            Some(Scope::Write)
        );
        assert_eq!(
            auth.scope_for(Some(&format!("Bearer {READ}"))),
            Some(Scope::Read)
        );
        // The scheme is case-insensitive (RFC 9110), the credential is not.
        assert_eq!(
            auth.scope_for(Some(&format!("bEaReR {WRITE}"))),
            Some(Scope::Write)
        );
        assert_eq!(
            auth.scope_for(Some(&format!("Bearer {}", WRITE.to_uppercase()))),
            None
        );
    }

    #[test]
    fn a_read_token_alone_never_grants_write() {
        let auth = HttpAuth::resolve(&env(None, Some(READ)), false).expect("resolve");
        assert_eq!(
            auth.scope_for(Some(&format!("Bearer {READ}"))),
            Some(Scope::Read)
        );
        // An unconfigured slot must not match by being empty on both sides.
        assert_eq!(auth.scope_for(Some(&format!("Bearer {WRITE}"))), None);
        assert_eq!(auth.scope_for(Some("Bearer ")), None);
    }

    #[test]
    fn missing_or_malformed_headers_grant_nothing() {
        let auth = HttpAuth::resolve(&env(Some(WRITE), Some(READ)), false).expect("resolve");
        for header in [
            None,
            Some(""),
            Some("Bearer"),
            Some("Bearer "),
            Some(WRITE),
            Some("Basic dXNlcjpwYXNz"),
            // A prefix of the real credential, and the real one with a
            // character added: neither is the credential.
            Some("Bearer 0123456789abcdef0123456789abcde"),
            Some("Bearer 0123456789abcdef0123456789abcdef0"),
            // A valid credential with something after it is not a bearer
            // credential this server understands.
            Some("Bearer 0123456789abcdef0123456789abcdef extra"),
        ] {
            assert_eq!(
                auth.scope_for(header),
                None,
                "{header:?} must not authorize"
            );
        }
    }

    /// The body of the named function, from its signature to its closing
    /// brace, with comment lines dropped — the prose around these two
    /// functions describes the very keywords the checks below look for.
    fn body_of(src: &'static str, signature: &str) -> String {
        let tail = src
            .split(signature)
            .nth(1)
            .unwrap_or_else(|| panic!("{signature} must exist"));
        let end = tail.find("\n    }").unwrap_or(0);
        tail[..end]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn token_comparison_is_constant_time_and_unconditional() {
        // Two properties no behavioural test can reach, because each mutant
        // returns exactly the same answers and differs only in how long it
        // takes to return them. The source is the only place to pin them.
        let src = include_str!("http_auth.rs");

        // 1. The comparison goes through `subtle`. A `==` here is a timing
        //    oracle on the token.
        let verifies = body_of(src, "fn verifies(&self, candidate: &str) -> bool {");
        assert!(
            verifies.contains("ct_eq"),
            "the comparison must use ct_eq: {verifies}"
        );
        assert!(
            !verifies.contains("=="),
            "the comparison must not use ==: {verifies}"
        );

        // 2. Every configured credential is compared, whatever the earlier
        //    ones said. Stopping at a hit would let a caller time the reply
        //    to learn which of the two secrets a guess collided with.
        let scope_for = body_of(src, "pub fn scope_for(&self, header: Option<&str>)");
        assert!(
            scope_for.contains("let candidate"),
            "scope_for must extract a credential first: {scope_for}"
        );
        // Everything after that extraction. The extraction line itself ends
        // in `?`, an early exit — but it happens before any comparison, so it
        // reveals nothing about a token.
        let after_extraction = scope_for
            .lines()
            .skip_while(|line| !line.contains("let candidate"))
            .skip(1)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            after_extraction.contains(".fold("),
            "scope_for must fold over every credential: {after_extraction}"
        );
        assert_eq!(
            after_extraction.matches("verifies(").count(),
            1,
            "one comparison site, applied to every credential: {after_extraction}"
        );
        for early_exit in ["return", "break", "if ", "else", "?"] {
            assert!(
                !after_extraction.contains(early_exit),
                "no {early_exit:?} may cut the comparison short: {after_extraction}"
            );
        }
    }

    #[test]
    fn stdio_ignores_tokens_and_the_insecure_flag() {
        // Every http startup refusal, offered to a stdio run: all accepted,
        // and none of them yields a gate. A mutation that resolved the gate
        // regardless of transport fails on the first of these.
        for (e, insecure) in [
            (HttpEnv::default(), false),
            (env(Some("short"), None), false),
            (env(Some(WRITE), Some(WRITE)), false),
            (env(Some(WRITE), None), true),
            (env(Some("not printable at all"), None), false),
        ] {
            let gate = resolve_for(Transport::Stdio, &e, insecure).expect("stdio never refuses");
            assert!(gate.is_none(), "stdio must resolve no bearer gate");
        }
        // The same environment over http is the refusal it should be.
        assert!(resolve_for(Transport::Http, &HttpEnv::default(), false).is_err());
    }

    #[test]
    fn refusal_logging_is_bounded_and_names_no_material() {
        let auth = HttpAuth::resolve(&env(Some(WRITE), None), false).expect("resolve");
        let ((), logs) = crate::testlog::capture_logs(|| {
            for _ in 0..5 {
                auth.note_refusal();
            }
        });
        // Five refusals, three lines: 1, 2, 4. A mutation that logged every
        // refusal — an unauthenticated log-volume lever — fails here.
        assert_eq!(
            logs.matches("http bearer authentication refused a request")
                .count(),
            3,
            "{logs}"
        );
        assert!(logs.contains("refused=4"), "{logs}");
        assert!(
            !logs.contains(WRITE),
            "the log must carry no token (I12): {logs}"
        );
    }

    #[test]
    fn the_startup_mode_line_never_carries_token_material() {
        for (e, insecure) in [
            (env(Some(WRITE), Some(READ)), false),
            (env(Some(WRITE), None), false),
            (env(None, Some(READ)), false),
            (HttpEnv::default(), true),
        ] {
            let auth = HttpAuth::resolve(&e, insecure).expect("resolve");
            let ((), logs) = crate::testlog::capture_logs(|| auth.log_startup_mode());
            // Positive first, so the I12 negative below is evidence and not
            // just an empty capture passing.
            assert!(
                logs.contains("http authentication:") || logs.contains("--insecure-no-auth"),
                "{logs}"
            );
            assert!(!logs.contains(WRITE), "{logs}");
            assert!(!logs.contains(READ), "{logs}");
        }
    }

    #[test]
    fn config_errors_name_the_variable_and_never_the_token() {
        let secret = "SUPERSECRETTOKENSUPERSECRETTOKEN";
        for e in [
            AuthConfigError::UnusableToken {
                var: WRITE_TOKEN_VAR,
                flaw: TokenFlaw::TooShort,
            },
            AuthConfigError::UnusableToken {
                var: READ_TOKEN_VAR,
                flaw: TokenFlaw::NotBearerSafe,
            },
            AuthConfigError::MissingCredential,
            AuthConfigError::ContradictoryOptOut,
            AuthConfigError::IndistinguishableScopes,
        ] {
            let msg = e.to_string();
            assert!(
                msg.contains("BUGWARDEN_HTTP_"),
                "the message must name a variable: {msg}"
            );
            assert!(!msg.contains(secret), "{msg}");
        }
    }
}
