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
pub const NOTIFICATION_MAX_LEN: usize = 64;

/// Default chunk size for upgrade parts.
pub const UPDATE_PART_SIZE: usize = 64000; // 64 kB
