use std::{array::TryFromSliceError, io, num::TryFromIntError};

use pwmp_msg::response::Response;

/// Errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Generic I/O error.
    #[error("I/O error: [{}] {inner}", inner.kind())]
    Io {
        #[from]
        inner: io::Error,
    },

    /// Address sytax or resolution error.
    #[error("Failed to parse or resolve specified address")]
    IllegalAddr,

    /// Server rejected the client.
    #[error("Handshake failed")]
    Handshake,

    /// Server sent an error.
    #[error("Server returned error: {0:?}")]
    Server(pwmp_msg::response::Response),

    /// Invalid message length.
    #[error("Message is too large to send")]
    MessageTooLarge,

    /// Invalid message length.
    #[error("Message length is zero, too large, or generaly invalid")]
    IllegalMessageLength,

    /// Integer conversion error.
    #[error("Failed to convert between integer types")]
    IntConversion(#[from] TryFromIntError),

    /// The provided buffer was not large enough.
    #[error("The provided buffer is too small")]
    InvalidBuffer,

    /// A message has been received twice.
    #[error("Duplicate message")]
    DuplicateMessage,

    /// Expected a response message, got request instead.
    #[error("not response")]
    NotResponse,

    /// Expected a request message, got response instead.
    #[error("parse")]
    MessageParse,

    /// Unexpected response.
    #[error("Received unexpected response: expected '{expected}', got '{got:?}'")]
    UnexpectedResponse {
        expected: &'static str,
        got: Response,
    },

    /// Malformed response.
    #[error("malformed response")]
    MalformedResponse,

    #[error("Slice length does not match the expected array length: {0}")]
    ArrayFromSliceSizeMismatch(#[from] TryFromSliceError),
}

impl Error {
    pub(crate) fn check_server_error(response: Response) -> Result<Response, Self> {
        match response {
            Response::Reject => Err(Self::Handshake),
            Response::InternalServerError
            | Response::RateLimitExceeded
            | Response::InvalidRequest => Err(Self::Server(response)),
            _ => Ok(response),
        }
    }
}
