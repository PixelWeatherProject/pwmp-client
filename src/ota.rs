use pwmp_msg::version::Version;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateStatus {
    /// Current formware is up to date.
    UpToDate,

    /// A new firmware is available.
    Available(Version),
}

impl From<UpdateStatus> for bool {
    fn from(value: UpdateStatus) -> Self {
        value == UpdateStatus::UpToDate
    }
}
