//! Yapsta's native wire protocol (docs/ARCHITECTURE.md § 6): the messages, the
//! error codes, the version constants and the frame codec. Used by the server,
//! Yapsta Client and Yapsta Bot. No sockets and no TLS here.
//!
//! The wire surface is add-only (§ 6.7); `tests/wire_surface.rs` enforces it.

mod debug;
pub mod frame;

/// The generated messages of `proto/yapsta/v1/yapsta.proto`.
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/yapsta.v1.rs"));
}

/// The ALPN protocol, on QUIC and on the TCP fallback (§ 6.1).
pub const ALPN: &[u8] = b"yapsta/1";

/// The current minor version (§ 6.7). Minor versions start at 1; 0 is invalid.
pub const MINOR_VERSION: u32 = 1;

/// Largest frame on the control stream and on TCP (§ 6.1).
pub const MAX_CONTROL_FRAME: usize = 1024 * 1024;

/// Largest frame on a QUIC request stream (§ 6.1).
pub const MAX_REQUEST_FRAME: usize = 16 * 1024 * 1024;

/// An error or close code as received. A newer peer can send codes this
/// version does not know; those are errors, never a normal close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireCode {
    Known(v1::ErrorCode),
    /// Not known to this version. Treat it as an error that closed the
    /// connection, and resume (§ 6.1).
    Unknown(i64),
}

impl WireCode {
    /// The code in an `Error` frame. Prefer this to prost's `Error::code()`,
    /// which maps an unknown code to `Unspecified` (a normal close).
    pub fn of_error(error: &v1::Error) -> Self {
        Self::from_i64(error.code.into())
    }

    /// A QUIC application close code (§ 6.1).
    pub fn of_close(code: u64) -> Self {
        i64::try_from(code).map_or(Self::Unknown(i64::MAX), Self::from_i64)
    }

    fn from_i64(code: i64) -> Self {
        i32::try_from(code)
            .ok()
            .and_then(|c| v1::ErrorCode::try_from(c).ok())
            .map_or(Self::Unknown(code), Self::Known)
    }

    /// Whether this is the normal close (`UNSPECIFIED`, code 0).
    pub fn is_normal_close(self) -> bool {
        self == Self::Known(v1::ErrorCode::Unspecified)
    }
}

impl v1::ErrorCode {
    /// The QUIC application close code for this code (§ 6.1).
    pub fn close_code(self) -> u64 {
        // Every value is a small non-negative number.
        self as i32 as u64
    }
}

impl v1::Error {
    /// An `Error` frame. The message is fixed server text (`&'static str`):
    /// never user content (§ 6.1). A *received* `Error.message` is still peer
    /// text: `Debug` redacts it (debug.rs), and it never goes into a log line.
    pub fn new(code: v1::ErrorCode, message: &'static str) -> Self {
        Self {
            code: code.into(),
            message: message.to_owned(),
            retry_after_ms: None,
        }
    }
}
