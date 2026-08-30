//! Session-id provenance for the streamable-HTTP transport.
//!
//! The `mcp-session-id` REQUEST header is not the session id. rmcp mints
//! the id *after* it has injected the HTTP request parts, so an
//! `initialize` request never carries one; and on the stateless path the
//! header reaches the handler unvalidated, because `has_session` runs only
//! on the session branch. Reading it therefore lost the id on exactly the
//! record meant to anchor a session, and copied a forgeable one onto
//! refusals (issue #180).
//!
//! [`AuditedSessionManager`] closes both: `SessionManager` receives the
//! minted id together with the owned message, and message extensions
//! travel verbatim into the handler's context — `RequestContext` for a
//! request, `NotificationContext` for a notification — so stamping
//! [`TransportSessionId`] there hands the handler the transport's own
//! value. Same seam rmcp uses for its `SessionRestoreMarker`.

use std::sync::Arc;

use futures_core::Stream;
use rmcp::model::{ClientJsonRpcMessage, GetExtensions as _, ServerJsonRpcMessage};
use rmcp::transport::streamable_http_server::session::{
    local::{LocalSessionManager, LocalSessionManagerError},
    EventStore, RestoreOutcome, ServerSseMessage, SessionId, SessionManager,
};

/// The transport-minted session id, carried to the handler in the request
/// extensions. `SessionId` is rmcp's `Arc<str>`.
///
/// The audit stream's only source for `SessionInfo::id` on http: present
/// exactly when the transport really opened a session, so a stateless
/// caller cannot supply one.
#[derive(Debug, Clone)]
pub struct TransportSessionId(pub SessionId);

/// [`LocalSessionManager`] with [`TransportSessionId`] stamped into every
/// message that becomes a handler context.
///
/// Everything else delegates unchanged — `restore_session` and
/// `event_store` included, so wiring either up later does not silently
/// fall back to the trait defaults this wrapper would otherwise inherit.
#[derive(Debug, Default)]
pub struct AuditedSessionManager {
    inner: LocalSessionManager,
}

/// Stamp `id` where the serve loop will move it into the handler's
/// context: `RequestContext::extensions` for a request,
/// `NotificationContext::extensions` for a notification.
///
/// Responses and errors are the client's answers to the server's own
/// requests: they reach no handler and have no extensions to stamp.
fn stamp(message: &mut ClientJsonRpcMessage, id: &SessionId) {
    match message {
        ClientJsonRpcMessage::Request(req) => {
            req.request
                .extensions_mut()
                .insert(TransportSessionId(id.clone()));
        }
        ClientJsonRpcMessage::Notification(notification) => {
            notification
                .notification
                .extensions_mut()
                .insert(TransportSessionId(id.clone()));
        }
        ClientJsonRpcMessage::Response(_) | ClientJsonRpcMessage::Error(_) => {}
    }
}

impl SessionManager for AuditedSessionManager {
    type Error = LocalSessionManagerError;
    type Transport = <LocalSessionManager as SessionManager>::Transport;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        self.inner.create_session().await
    }

    /// The `initialize` request — the one message whose id exists only
    /// here, minted between the parts injection and this call.
    async fn initialize_session(
        &self,
        id: &SessionId,
        mut message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        stamp(&mut message, id);
        self.inner.initialize_session(id, message).await
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        self.inner.has_session(id).await
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.inner.close_session(id).await
    }

    /// Every in-session request: `id` is the header value rmcp already
    /// checked against `has_session`, so the stamp is the validated one.
    async fn create_stream(
        &self,
        id: &SessionId,
        mut message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        stamp(&mut message, id);
        self.inner.create_stream(id, message).await
    }

    /// In-session notifications, `notifications/initialized` included.
    /// Defensive today and deliberately untested: this build implements no
    /// notification handler, so no notification produces a record and
    /// deleting this stamp fails nothing. It is here so the first one that
    /// does is anchored rather than silently id-less.
    async fn accept_message(
        &self,
        id: &SessionId,
        mut message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        stamp(&mut message, id);
        self.inner.accept_message(id, message).await
    }

    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.inner.create_standalone_stream(id).await
    }

    async fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.inner.resume(id, last_event_id).await
    }

    async fn restore_session(
        &self,
        id: SessionId,
    ) -> Result<RestoreOutcome<Self::Transport>, Self::Error> {
        self.inner.restore_session(id).await
    }

    fn event_store(&self) -> Option<Arc<dyn EventStore>> {
        self.inner.event_store()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::{
        ClientNotification, ClientRequest, ClientResult, ErrorData, InitializedNotification,
        JsonRpcMessage, PingRequest, RequestId,
    };

    fn session() -> SessionId {
        SessionId::from("sess-180")
    }

    fn stamped(message: &ClientJsonRpcMessage) -> Option<&str> {
        let extensions = match message {
            ClientJsonRpcMessage::Request(req) => req.request.extensions(),
            ClientJsonRpcMessage::Notification(notification) => {
                notification.notification.extensions()
            }
            ClientJsonRpcMessage::Response(_) | ClientJsonRpcMessage::Error(_) => return None,
        };
        extensions.get::<TransportSessionId>().map(|id| &*id.0)
    }

    #[test]
    fn stamp_reaches_a_request() {
        // The tool-call shape: without this the in-session records lose
        // their id entirely, since nothing else carries it any more.
        let mut message = ClientJsonRpcMessage::request(
            ClientRequest::PingRequest(PingRequest::default()),
            RequestId::Number(1),
        );
        stamp(&mut message, &session());
        assert_eq!(stamped(&message), Some("sess-180"));
    }

    #[test]
    fn stamp_reaches_a_notification() {
        // `notifications/initialized` arrives through `accept_message`,
        // the third call site — a stamp on requests alone would leave any
        // notification-driven record unanchored.
        let mut message = ClientJsonRpcMessage::notification(
            ClientNotification::InitializedNotification(InitializedNotification::default()),
        );
        stamp(&mut message, &session());
        assert_eq!(stamped(&message), Some("sess-180"));
    }

    #[test]
    fn stamp_leaves_responses_and_errors_alone() {
        // Client answers to server-initiated requests: they reach no
        // handler and have no extensions to stamp. Compared as serialized
        // JSON, since extensions are not part of the wire form — what this
        // pins is that the arm is a no-op on everything the message does
        // carry, variant included.
        let json =
            |m: &ClientJsonRpcMessage| serde_json::to_value(m).expect("a message serializes");

        let mut response =
            ClientJsonRpcMessage::response(ClientResult::empty(()), RequestId::Number(7));
        let before = json(&response);
        stamp(&mut response, &session());
        assert!(matches!(response, ClientJsonRpcMessage::Response(_)));
        assert_eq!(json(&response), before);

        let mut error = JsonRpcMessage::error(
            ErrorData::internal_error("boom", None),
            Some(RequestId::Number(7)),
        );
        let before = json(&error);
        stamp(&mut error, &session());
        assert!(matches!(error, ClientJsonRpcMessage::Error(_)));
        assert_eq!(json(&error), before);
    }
}
