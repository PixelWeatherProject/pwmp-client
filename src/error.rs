use std::io;

/// Errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Generic I/O error.
    #[error("I/O error: [{}] {inner}", inner.kind())]
    Io {
        #[from]
        inner: io::Error,
    },

    /// Handshake failed.
    #[error("Handshake authentication failed: {0:?}")]
    HandshakeFailed(Option<Box<str>>),

    /// Expected a response message, got request instead.
    #[error("Expected response, got request instead")]
    NotResponse,

    /// Expected a request message, got response instead.
    #[error("Failed to de/serialize the message")]
    MessageParse,

    /// Unexpected variant of a response or request.
    #[error("Unexpected request/response variant")]
    UnexpectedVariant,

    /// Malformed response.
    #[error("Malformed response")]
    MalformedResponse,
}
