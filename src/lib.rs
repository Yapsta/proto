//! Yapsta's native wire protocol (docs/ARCHITECTURE.md § 6): the messages, the
//! error codes, the version constants and the frame codec. Used by the server,
//! Yapsta Client and Yapsta Bot. No sockets and no TLS here.
//!
//! The wire surface is add-only (§ 6.7); `tests/wire_surface.rs` enforces it.

mod debug;
pub mod frame;
pub mod identity;

/// The generated messages of `proto/yapsta/v1/yapsta.proto`.
#[allow(
    clippy::large_enum_variant,
    reason = "generated oneofs, sized by their largest message (a snapshot beside an Ack); \
              boxing would change the API the client and bot repos build against"
)]
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/yapsta.v1.rs"));
}

/// The ALPN protocol, on QUIC and on the TCP fallback (§ 6.1).
pub const ALPN: &[u8] = b"yapsta/1";

/// The newest minor version this crate defines (§ 6.7): 3 = M3. Minor
/// versions start at 1; 0 is invalid. A client sends the minor it implements,
/// not this constant by default: a client that speaks minor 3 must handle the
/// M3 events, ephemerals and snapshot fields (§ 6.3, § 6.9).
pub const MINOR_VERSION: u32 = 3;

/// The minors the server accepts, highest first: `Hello.versions` (§ 6.7).
/// The current and the previous one; minor 1 (M1) is no longer accepted.
pub const SUPPORTED_MINORS: &[u32] = &[3, 2];

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

impl v1::Permission {
    /// This permission's bit in a `fixed64` permission set: value N is bit
    /// N - 1 (§ 8.3). `None` for `UNSPECIFIED`.
    pub fn bit(self) -> Option<u64> {
        // Every value is a small non-negative number.
        (self as i32 as u32).checked_sub(1).map(|n| 1 << n)
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
            device_list: None,
        }
    }
}

/// The minor that introduced an envelope body, looking inside a `Command` or
/// `Request` at its kind (§ 6.7): a session on an older minor that sends it is
/// answered `INVALID`. An unset body or kind is minor 1: it is refused as
/// unknown, not for its version. Exhaustive, so a new body or kind does not
/// compile until it is classified here.
pub fn minor_of(body: &v1::envelope::Body) -> u32 {
    use v1::envelope::Body;
    match body {
        Body::Error(_)
        | Body::Hello(_)
        | Body::Auth(_)
        | Body::Welcome(_)
        | Body::Event(_)
        | Body::Ephemeral(_)
        | Body::SetPresence(_)
        | Body::Ack(_)
        | Body::Ping(_) => 1,
        Body::Redeem(_) | Body::Resync(_) | Body::CommandResult(_) | Body::Response(_) => 2,
        Body::Command(command) => command.kind.as_ref().map_or(2, command_minor),
        Body::Request(request) => request.kind.as_ref().map_or(2, request_minor),
        Body::StartTyping(_) => 3,
    }
}

/// The minor that introduced a command kind (§ 6.7).
pub fn command_minor(kind: &v1::command::Kind) -> u32 {
    use v1::command::Kind;
    match kind {
        Kind::GetSpace(_)
        | Kind::UpdateSpace(_)
        | Kind::SetSpaceIcon(_)
        | Kind::FetchSpaceIcon(_)
        | Kind::CreateChannel(_)
        | Kind::UpdateChannel(_)
        | Kind::MoveChannel(_)
        | Kind::DeleteChannel(_)
        | Kind::SetChannelPassword(_)
        | Kind::GetChannel(_)
        | Kind::CreateRole(_)
        | Kind::UpdateRole(_)
        | Kind::MoveRole(_)
        | Kind::DeleteRole(_)
        | Kind::AddMemberRole(_)
        | Kind::RemoveMemberRole(_)
        | Kind::SetOverwrite(_)
        | Kind::DeleteOverwrite(_)
        | Kind::GetMember(_)
        | Kind::UpdateProfile(_)
        | Kind::SetAvatar(_)
        | Kind::SetNickname(_)
        | Kind::CreateInvite(_)
        | Kind::ListInvites(_)
        | Kind::RevokeInvite(_)
        | Kind::TransferMember(_)
        | Kind::TransferOwnership(_) => 2,
        Kind::SendMessage(_)
        | Kind::EditMessage(_)
        | Kind::DeleteMessage(_)
        | Kind::AddReaction(_)
        | Kind::RemoveReaction(_)
        | Kind::PinMessage(_)
        | Kind::UnpinMessage(_)
        | Kind::CreateThread(_)
        | Kind::UpdateThread(_)
        | Kind::MarkRead(_)
        | Kind::Poke(_)
        | Kind::CreateEmoji(_)
        | Kind::RenameEmoji(_)
        | Kind::DeleteEmoji(_) => 3,
    }
}

/// The minor that introduced a request kind (§ 6.7).
pub fn request_minor(kind: &v1::request::Kind) -> u32 {
    use v1::request::Kind;
    match kind {
        Kind::MemberPage(_) | Kind::FetchBlob(_) | Kind::UploadImage(_) => 2,
        Kind::MessageHistory(_)
        | Kind::GetMessages(_)
        | Kind::ListPins(_)
        | Kind::ListThreads(_)
        | Kind::Search(_)
        | Kind::UploadAttachment(_)
        | Kind::FetchAttachment(_)
        | Kind::AttachmentUrl(_)
        | Kind::UploadUrl(_) => 3,
    }
}
