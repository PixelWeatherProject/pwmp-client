#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateStatus {
    /// Current formware is up to date.
    UpToDate,

    /// A new firmware is available.
    /// The tuple contains the major, middle and minor version numbers.
    Available(u8, u8, u8),
}

impl From<UpdateStatus> for bool {
    fn from(value: UpdateStatus) -> Self {
        value == UpdateStatus::UpToDate
    }
}
