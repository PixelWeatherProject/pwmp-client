use std::time::Duration;

/// Receive buffer size for sockets.
pub const RCV_BUFFER_SIZE: usize = 96;

/// Default connection timeout.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Default read timeout.
pub const READ_TIMEOUT: Duration = Duration::from_secs(4);

/// Default write timeout.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(4);

/// Maximum length of notification contents.
pub const NOTIFICATION_MAX_LEN: usize = 1024;

/// Maximum allowed size for update chunk requests.
pub const UPDATE_BLOB_MAX_LEN: u32 = 4_194_304; // 4 MiB

/// Default chunk size for upgrade parts.
pub const UPDATE_BLOB_DEFAULT_LEN: u32 = 1024; // 1 kB

/// Maximum allowed size of diagnostic artifacts.
pub const DIAG_DATA_MAX_LEN: usize = 4_194_304; // 4 MiB
