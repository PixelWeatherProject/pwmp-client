use super::{DIAG_DATA_MAX_LEN, NOTIFICATION_MAX_LEN, UPDATE_BLOB_MAX_LEN};
use pwmp_msg::response::Response;
use std::{array::TryFromSliceError, io, num::TryFromIntError};

/// Errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to serialize a message.
    #[error("Serialize: {0}")]
    Serialize(pwmp_msg::postcard::Error),

    /// Failed to serialize a message.
    #[error("Deserialize: {0}")]
    Deserialize(pwmp_msg::postcard::Error),

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

    /// Maximum notification length exceeded.
    #[error("Maximum notification length exceeded ({NOTIFICATION_MAX_LEN} allowed, {0} provided)")]
    IllegalNotificationLength(usize),

    /// Diagnostic artifact tag is empty or contains illegal characters.
    #[error("Diagnostic artifact tag is empty or contains illegal characters")]
    IllegalDiagArtifactTag,

    /// Diagnostic artifact content is empty or too large.
    #[error(
        "Diagnostic artifact size must be between 1 and {DIAG_DATA_MAX_LEN} bytes ({0} provided)"
    )]
    IllegalDiagArtifactSize(usize),

    /// Requested update chunk size is too large.
    #[error("Maximum update chunk size exceeded ({UPDATE_BLOB_MAX_LEN} allowed, {0} requested)")]
    IllegalUpdateRequestSize(u32),

    /// Invalid message length.
    #[error("Message is too large to send")]
    MessageTooLarge,

    /// Invalid message length.
    #[error("Message length is zero, too large, or generaly invalid")]
    IllegalMessageLength,

    /// Integer conversion error.
    #[error("Failed to convert between integer types")]
    IntConversion(#[from] TryFromIntError),

    /// Float value is NaN, infinite, or out of range for the target integer type.
    #[error("Value {0} cannot be represented in the target unit")]
    IllegalValue(f32),

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

    /// Slice length does not match the expected array length
    #[error("Slice length does not match the expected array length: {0}")]
    ArrayFromSliceSizeMismatch(#[from] TryFromSliceError),

    /// Server did not process session termination successfully.
    #[error("Server did not process `Bye` message (read {read_count}, err {io_err:?})")]
    UnprocessedBye {
        io_err: Option<std::io::Error>,
        read_count: usize,
    },
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
