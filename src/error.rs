use thiserror::Error;

/// One error type for the whole crate. Every fallible function returns
/// this, so the engine's fail-open handler can match on a single type.
#[derive(Debug, Error)]
pub enum DpiGuardError {
    #[error("packet too short: need {need} bytes, have {have}")]
    PacketTooShort { need: usize, have: usize },

    #[error("SNI not found in ClientHello")]
    SniNotFound,

    #[error("TLS record is not a ClientHello")]
    NotClientHello,

    #[error("value out of range: {0}")]
    OutOfRange(String),

    #[error("this feature needs Windows + WinDivert, running on {os}")]
    PlatformNotSupported { os: &'static str },

    #[error("WinDivert driver error: {0}")]
    Driver(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("DNS resolution error: {0}")]
    Resolution(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
