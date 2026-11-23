//! Yapsta's native wire protocol (docs/PROTOCOL.md § 6): the messages, the
//! error codes, the version constants and the frame codec. Used by the server,
//! Yapsta Client and Yapsta Bot. No sockets and no TLS here.
//!
//! The wire surface is add-only (§ 6.7); `tests/wire_surface.rs` enforces it.

mod bound;
mod debug;
pub mod frame;
pub mod identity;
pub mod voice;

/// The generated messages of `proto/yapsta/v1/yapsta.proto`.
#[allow(
    clippy::large_enum_variant,
    reason = "generated oneofs, sized by their largest message (a snapshot beside an Ack); \
              boxing would change the API the client and bot repos build against"
)]
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/yapsta.v1.rs"));
}

/// The `.proto` source this crate compiles (`proto/yapsta/v1/yapsta.proto`),
/// for a consumer's tests that check names against the wire definition.
pub const PROTO_SOURCE: &str = include_str!("../proto/yapsta/v1/yapsta.proto");

/// The committed wire surface (`tests/wire_surface.txt`, § 6.7): every field
/// and enum value with its number and type, one per line, for a consumer's
/// tests that check a message's shape.
pub const WIRE_SURFACE: &str = include_str!("../tests/wire_surface.txt");

/// The ALPN protocol, on QUIC and on the TCP fallback (§ 6.1).
pub const ALPN: &[u8] = b"yapsta/1";

/// The newest minor version this crate defines (§ 6.7): 10 = M10. Minor
/// versions start at 1; 0 is invalid. A client sends the minor it implements,
/// not this constant by default: a client that speaks minor 10 must handle the
/// M10 surface (the personal stream, § 6.3; DMs, § 6.17; push, § 6.18).
pub const MINOR_VERSION: u32 = 10;

/// The minors the server accepts, highest first: `Hello.versions` (§ 6.7).
/// The current and the previous one; minor 8 (M8) is no longer accepted.
pub const SUPPORTED_MINORS: &[u32] = &[10, 9];

/// Largest frame on the control stream and on TCP (§ 6.1).
pub const MAX_CONTROL_FRAME: usize = 1024 * 1024;

/// Largest frame on a QUIC request stream (§ 6.1).
pub const MAX_REQUEST_FRAME: usize = 16 * 1024 * 1024;
/// Largest frame a client may send before its `Welcome`, and on a
/// non-member session (§ 6.1, § 6.16). The largest legal `Auth` is under
/// 18 KiB.
pub const MAX_RESTRICTED_FRAME: usize = 32 * 1024;

/// The most heap a frame on the control stream or TCP may decode to, by
/// [`frame::decoded_bound`] (§ 6.1): 16 times [`MAX_CONTROL_FRAME`]. A frame
/// over it is `TOO_LARGE` before it is decoded.
pub const MAX_CONTROL_DECODED: usize = 16 * MAX_CONTROL_FRAME;

/// The most heap a frame on a QUIC request stream may decode to (§ 6.1):
/// 4 times [`MAX_REQUEST_FRAME`]. A reply that large is mostly file bytes,
/// which decode to their own size.
pub const MAX_REQUEST_DECODED: usize = 4 * MAX_REQUEST_FRAME;

/// The most heap a frame under [`MAX_RESTRICTED_FRAME`] may decode to
/// (§ 6.16): 8 times the frame. The largest legal `Auth` decodes to under
/// 20 KiB.
pub const MAX_RESTRICTED_DECODED: usize = 8 * MAX_RESTRICTED_FRAME;

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
        // § 6.14: the open-join variant is minor 7; the codes are minor 2.
        Body::Redeem(v1::Redeem {
            code: Some(v1::redeem::Code::OpenJoin(_)),
        }) => 7,
        Body::Redeem(_) | Body::Resync(_) | Body::CommandResult(_) | Body::Response(_) => 2,
        Body::Command(command) => command.kind.as_ref().map_or(2, command_minor),
        Body::Request(request) => request.kind.as_ref().map_or(2, request_minor),
        Body::StartTyping(_) => 3,
        // § 6.3: server-only bodies, refused from their tag before decoding
        // when a client sends one (frame.rs); classified for completeness.
        Body::Personal(_) | Body::PersonalSnapshot(_) => 10,
    }
}

/// Each command kind's name for metrics labels (§ 6.13), at its
/// [`command_kind_index`]: its field name in `Command.kind`.
pub const COMMAND_KIND_NAMES: [&str; 85] = [
    "get_space",
    "update_space",
    "set_space_icon",
    "fetch_space_icon",
    "create_channel",
    "update_channel",
    "move_channel",
    "delete_channel",
    "set_channel_password",
    "get_channel",
    "create_role",
    "update_role",
    "move_role",
    "delete_role",
    "add_member_role",
    "remove_member_role",
    "set_overwrite",
    "delete_overwrite",
    "get_member",
    "update_profile",
    "set_avatar",
    "set_nickname",
    "create_invite",
    "list_invites",
    "revoke_invite",
    "transfer_member",
    "transfer_ownership",
    "send_message",
    "edit_message",
    "delete_message",
    "add_reaction",
    "remove_reaction",
    "pin_message",
    "unpin_message",
    "create_thread",
    "update_thread",
    "mark_read",
    "poke",
    "create_emoji",
    "rename_emoji",
    "delete_emoji",
    "join_voice",
    "leave_voice",
    "set_voice_state",
    "set_member_voice",
    "move_member",
    "disconnect_member",
    "set_whisper_list",
    "clear_whisper_list",
    "apply_template",
    "kick_member",
    "ban_member",
    "unban_member",
    "timeout_member",
    "publish_media",
    "unpublish_media",
    "subscribe_media",
    "answer_media",
    "unsubscribe_media",
    "create_bot",
    "rotate_bot",
    "delete_bot",
    "register_commands",
    "invoke_command",
    "create_webhook",
    "delete_webhook",
    "delete_thread",
    "open_dm",
    "create_group_dm",
    "add_dm_member",
    "remove_dm_member",
    "leave_dm",
    "update_dm",
    "send_dm_message",
    "edit_dm_message",
    "delete_dm_message",
    "add_dm_reaction",
    "remove_dm_reaction",
    "mark_dm_read",
    "block",
    "unblock",
    "set_notification_setting",
    "register_push",
    "unregister_push",
    "go_background",
];

/// A command kind's place in [`COMMAND_KIND_NAMES`]. Exhaustive, so a new
/// kind needs its place (and name) here; a metrics table is indexed by it.
pub fn command_kind_index(kind: &v1::command::Kind) -> usize {
    use v1::command::Kind;
    match kind {
        Kind::GetSpace(_) => 0,
        Kind::UpdateSpace(_) => 1,
        Kind::SetSpaceIcon(_) => 2,
        Kind::FetchSpaceIcon(_) => 3,
        Kind::CreateChannel(_) => 4,
        Kind::UpdateChannel(_) => 5,
        Kind::MoveChannel(_) => 6,
        Kind::DeleteChannel(_) => 7,
        Kind::SetChannelPassword(_) => 8,
        Kind::GetChannel(_) => 9,
        Kind::CreateRole(_) => 10,
        Kind::UpdateRole(_) => 11,
        Kind::MoveRole(_) => 12,
        Kind::DeleteRole(_) => 13,
        Kind::AddMemberRole(_) => 14,
        Kind::RemoveMemberRole(_) => 15,
        Kind::SetOverwrite(_) => 16,
        Kind::DeleteOverwrite(_) => 17,
        Kind::GetMember(_) => 18,
        Kind::UpdateProfile(_) => 19,
        Kind::SetAvatar(_) => 20,
        Kind::SetNickname(_) => 21,
        Kind::CreateInvite(_) => 22,
        Kind::ListInvites(_) => 23,
        Kind::RevokeInvite(_) => 24,
        Kind::TransferMember(_) => 25,
        Kind::TransferOwnership(_) => 26,
        Kind::SendMessage(_) => 27,
        Kind::EditMessage(_) => 28,
        Kind::DeleteMessage(_) => 29,
        Kind::AddReaction(_) => 30,
        Kind::RemoveReaction(_) => 31,
        Kind::PinMessage(_) => 32,
        Kind::UnpinMessage(_) => 33,
        Kind::CreateThread(_) => 34,
        Kind::UpdateThread(_) => 35,
        Kind::MarkRead(_) => 36,
        Kind::Poke(_) => 37,
        Kind::CreateEmoji(_) => 38,
        Kind::RenameEmoji(_) => 39,
        Kind::DeleteEmoji(_) => 40,
        Kind::JoinVoice(_) => 41,
        Kind::LeaveVoice(_) => 42,
        Kind::SetVoiceState(_) => 43,
        Kind::SetMemberVoice(_) => 44,
        Kind::MoveMember(_) => 45,
        Kind::DisconnectMember(_) => 46,
        Kind::SetWhisperList(_) => 47,
        Kind::ClearWhisperList(_) => 48,
        Kind::ApplyTemplate(_) => 49,
        Kind::KickMember(_) => 50,
        Kind::BanMember(_) => 51,
        Kind::UnbanMember(_) => 52,
        Kind::TimeoutMember(_) => 53,
        Kind::PublishMedia(_) => 54,
        Kind::UnpublishMedia(_) => 55,
        Kind::SubscribeMedia(_) => 56,
        Kind::AnswerMedia(_) => 57,
        Kind::UnsubscribeMedia(_) => 58,
        Kind::CreateBot(_) => 59,
        Kind::RotateBot(_) => 60,
        Kind::DeleteBot(_) => 61,
        Kind::RegisterCommands(_) => 62,
        Kind::InvokeCommand(_) => 63,
        Kind::CreateWebhook(_) => 64,
        Kind::DeleteWebhook(_) => 65,
        Kind::DeleteThread(_) => 66,
        Kind::OpenDm(_) => 67,
        Kind::CreateGroupDm(_) => 68,
        Kind::AddDmMember(_) => 69,
        Kind::RemoveDmMember(_) => 70,
        Kind::LeaveDm(_) => 71,
        Kind::UpdateDm(_) => 72,
        Kind::SendDmMessage(_) => 73,
        Kind::EditDmMessage(_) => 74,
        Kind::DeleteDmMessage(_) => 75,
        Kind::AddDmReaction(_) => 76,
        Kind::RemoveDmReaction(_) => 77,
        Kind::MarkDmRead(_) => 78,
        Kind::Block(_) => 79,
        Kind::Unblock(_) => 80,
        Kind::SetNotificationSetting(_) => 81,
        Kind::RegisterPush(_) => 82,
        Kind::UnregisterPush(_) => 83,
        Kind::GoBackground(_) => 84,
    }
}

/// A command kind's name for metrics labels (§ 6.13): its field name in
/// `Command.kind`.
pub fn command_kind_name(kind: &v1::command::Kind) -> &'static str {
    COMMAND_KIND_NAMES[command_kind_index(kind)]
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
        Kind::JoinVoice(_)
        | Kind::LeaveVoice(_)
        | Kind::SetVoiceState(_)
        | Kind::SetMemberVoice(_)
        | Kind::MoveMember(_)
        | Kind::DisconnectMember(_)
        | Kind::SetWhisperList(_)
        | Kind::ClearWhisperList(_) => 4,
        Kind::ApplyTemplate(_) => 5,
        Kind::KickMember(_)
        | Kind::BanMember(_)
        | Kind::UnbanMember(_)
        | Kind::TimeoutMember(_) => 6,
        // § 6.6.
        Kind::PublishMedia(_)
        | Kind::UnpublishMedia(_)
        | Kind::SubscribeMedia(_)
        | Kind::AnswerMedia(_)
        | Kind::UnsubscribeMedia(_) => 7,
        // § 6.15.
        Kind::CreateBot(_)
        | Kind::RotateBot(_)
        | Kind::DeleteBot(_)
        | Kind::RegisterCommands(_)
        | Kind::InvokeCommand(_)
        | Kind::CreateWebhook(_)
        | Kind::DeleteWebhook(_) => 8,
        // § 6.16.
        Kind::DeleteThread(_) => 9,
        // § 6.17, § 6.18.
        Kind::OpenDm(_)
        | Kind::CreateGroupDm(_)
        | Kind::AddDmMember(_)
        | Kind::RemoveDmMember(_)
        | Kind::LeaveDm(_)
        | Kind::UpdateDm(_)
        | Kind::SendDmMessage(_)
        | Kind::EditDmMessage(_)
        | Kind::DeleteDmMessage(_)
        | Kind::AddDmReaction(_)
        | Kind::RemoveDmReaction(_)
        | Kind::MarkDmRead(_)
        | Kind::Block(_)
        | Kind::Unblock(_)
        | Kind::SetNotificationSetting(_)
        | Kind::RegisterPush(_)
        | Kind::UnregisterPush(_)
        | Kind::GoBackground(_) => 10,
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
        Kind::AuditPage(_) | Kind::BanList(_) => 6,
        // § 6.6.
        Kind::TurnCredentials(_) => 7,
        // § 6.15.
        Kind::BotList(_) | Kind::CommandList(_) | Kind::WebhookList(_) => 8,
        // § 6.17.
        Kind::DmHistory(_) | Kind::ListDms(_) => 10,
    }
}

#[cfg(test)]
mod kind_name_tests {
    use std::collections::HashSet;

    use prost::Message;

    use super::*;

    /// Each kind's name is its own field's name in `Command.kind`: a
    /// one-field `Command` per `oneof kind` line of the proto file, decoded,
    /// names the field it was encoded with. So the label is what a client
    /// sees on the wire, and no two kinds share or swap a name.
    #[test]
    fn command_kind_names_are_the_field_names() {
        let proto = include_str!("../proto/yapsta/v1/yapsta.proto");
        let start = proto.find("message Command {").expect("Command");
        let oneof = &proto[start..];
        let oneof = &oneof[oneof.find("oneof kind {").expect("oneof kind")..];
        let oneof = &oneof[..oneof.find('}').expect("closed")];
        let mut names = HashSet::new();
        for line in oneof.lines().skip(1) {
            // `Type name = N [options]; // comment`
            let line = line.split("//").next().unwrap_or_default();
            let line = line.split('[').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let (field, number) = line.split_once(" = ").expect(line);
            let name = field.split_whitespace().nth(1).expect(line);
            let number: u64 = number.trim_end_matches(';').trim().parse().expect(line);
            // The field's key (wire type 2, length-delimited) as a varint,
            // then an empty message.
            let mut key = (number << 3) | 2;
            let mut bytes = Vec::new();
            while key >= 0x80 {
                bytes.push((key as u8) | 0x80);
                key >>= 7;
            }
            bytes.push(key as u8);
            bytes.push(0);
            let command = v1::Command::decode(bytes.as_slice()).expect(line);
            let kind = command.kind.expect(line);
            assert_eq!(command_kind_name(&kind), name, "field {number}");
            assert!(names.insert(name), "{name} twice");
        }
        assert!(names.len() >= 50, "{}", names.len());
        // Every place in the table is some field's: none left over.
        assert_eq!(names.len(), COMMAND_KIND_NAMES.len());
    }
}
