//! Yapsta's native wire protocol (docs/ARCHITECTURE.md § 6): the messages, the
//! error codes, the version constants and the frame codec. Used by the server,
//! Yapsta Client and Yapsta Bot. No sockets and no TLS here.
//!
//! The wire surface is add-only (§ 6.7); `tests/wire_surface.rs` enforces it.

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

/// The ALPN protocol, on QUIC and on the TCP fallback (§ 6.1).
pub const ALPN: &[u8] = b"yapsta/1";

/// The newest minor version this crate defines (§ 6.7): 8 = M8. Minor
/// versions start at 1; 0 is invalid. A client sends the minor it implements,
/// not this constant by default: a client that speaks minor 8 must handle the
/// M8 surface (bots, § 6.15).
pub const MINOR_VERSION: u32 = 8;

/// The minors the server accepts, highest first: `Hello.versions` (§ 6.7).
/// The current and the previous one; minor 6 (M6) is no longer accepted.
pub const SUPPORTED_MINORS: &[u32] = &[8, 7];

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
        // § 6.14: the open-join variant is minor 7; the codes are minor 2.
        Body::Redeem(v1::Redeem {
            code: Some(v1::redeem::Code::OpenJoin(_)),
        }) => 7,
        Body::Redeem(_) | Body::Resync(_) | Body::CommandResult(_) | Body::Response(_) => 2,
        Body::Command(command) => command.kind.as_ref().map_or(2, command_minor),
        Body::Request(request) => request.kind.as_ref().map_or(2, request_minor),
        Body::StartTyping(_) => 3,
    }
}

/// A command kind's name for metrics labels (§ 6.13): its field name in
/// `Command.kind`. Exhaustive, so a new kind needs its name here.
pub fn command_kind_name(kind: &v1::command::Kind) -> &'static str {
    use v1::command::Kind;
    match kind {
        Kind::GetSpace(_) => "get_space",
        Kind::UpdateSpace(_) => "update_space",
        Kind::SetSpaceIcon(_) => "set_space_icon",
        Kind::FetchSpaceIcon(_) => "fetch_space_icon",
        Kind::CreateChannel(_) => "create_channel",
        Kind::UpdateChannel(_) => "update_channel",
        Kind::MoveChannel(_) => "move_channel",
        Kind::DeleteChannel(_) => "delete_channel",
        Kind::SetChannelPassword(_) => "set_channel_password",
        Kind::GetChannel(_) => "get_channel",
        Kind::CreateRole(_) => "create_role",
        Kind::UpdateRole(_) => "update_role",
        Kind::MoveRole(_) => "move_role",
        Kind::DeleteRole(_) => "delete_role",
        Kind::AddMemberRole(_) => "add_member_role",
        Kind::RemoveMemberRole(_) => "remove_member_role",
        Kind::SetOverwrite(_) => "set_overwrite",
        Kind::DeleteOverwrite(_) => "delete_overwrite",
        Kind::GetMember(_) => "get_member",
        Kind::UpdateProfile(_) => "update_profile",
        Kind::SetAvatar(_) => "set_avatar",
        Kind::SetNickname(_) => "set_nickname",
        Kind::CreateInvite(_) => "create_invite",
        Kind::ListInvites(_) => "list_invites",
        Kind::RevokeInvite(_) => "revoke_invite",
        Kind::TransferMember(_) => "transfer_member",
        Kind::TransferOwnership(_) => "transfer_ownership",
        Kind::SendMessage(_) => "send_message",
        Kind::EditMessage(_) => "edit_message",
        Kind::DeleteMessage(_) => "delete_message",
        Kind::AddReaction(_) => "add_reaction",
        Kind::RemoveReaction(_) => "remove_reaction",
        Kind::PinMessage(_) => "pin_message",
        Kind::UnpinMessage(_) => "unpin_message",
        Kind::CreateThread(_) => "create_thread",
        Kind::UpdateThread(_) => "update_thread",
        Kind::MarkRead(_) => "mark_read",
        Kind::Poke(_) => "poke",
        Kind::CreateEmoji(_) => "create_emoji",
        Kind::RenameEmoji(_) => "rename_emoji",
        Kind::DeleteEmoji(_) => "delete_emoji",
        Kind::JoinVoice(_) => "join_voice",
        Kind::LeaveVoice(_) => "leave_voice",
        Kind::SetVoiceState(_) => "set_voice_state",
        Kind::SetMemberVoice(_) => "set_member_voice",
        Kind::MoveMember(_) => "move_member",
        Kind::DisconnectMember(_) => "disconnect_member",
        Kind::SetWhisperList(_) => "set_whisper_list",
        Kind::ClearWhisperList(_) => "clear_whisper_list",
        Kind::ApplyTemplate(_) => "apply_template",
        Kind::KickMember(_) => "kick_member",
        Kind::BanMember(_) => "ban_member",
        Kind::UnbanMember(_) => "unban_member",
        Kind::TimeoutMember(_) => "timeout_member",
        Kind::PublishMedia(_) => "publish_media",
        Kind::UnpublishMedia(_) => "unpublish_media",
        Kind::SubscribeMedia(_) => "subscribe_media",
        Kind::AnswerMedia(_) => "answer_media",
        Kind::UnsubscribeMedia(_) => "unsubscribe_media",
        Kind::CreateBot(_) => "create_bot",
        Kind::RotateBot(_) => "rotate_bot",
        Kind::DeleteBot(_) => "delete_bot",
        Kind::RegisterCommands(_) => "register_commands",
        Kind::InvokeCommand(_) => "invoke_command",
        Kind::CreateWebhook(_) => "create_webhook",
        Kind::DeleteWebhook(_) => "delete_webhook",
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
    }
}
