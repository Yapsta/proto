//! `Debug` for the messages that carry a secret (resume tokens, redeem codes,
//! channel passwords), user text (client info, custom status, names, profiles)
//! or other bytes a peer fills freely (error text, signed device-list bodies,
//! blobs): the shape and lengths only. ARCHITECTURE § 6.2
//! and § 6.3 say these are never logged; this keeps a stray `{:?}` from doing so.
//!
//! The messages are listed in `redacted_debug.txt` (read by build.rs), and
//! `tests/wire_surface.rs` fails on any text field that is neither redacted nor
//! listed as public. Each impl destructures its message without `..`, so a new
//! field is a compile error here rather than a silent omission.

use std::fmt;
use std::marker::PhantomData;

use crate::v1::{
    BlobData, Channel, ChannelKind, ClientInfo, CreateChannel, CreateEmoji, CreateRole,
    CreateThread, CustomEmoji, EditMessage, EmojiRef, Error, ErrorCode, ImagePurpose,
    InviteCreated, JoinVoice, Member, Message, Poke, PokeMember, PresenceStatus, PresenceUpdate,
    Redeem, RenameEmoji, Resume, Role, SearchRequest, SendMessage, SetChannelPassword, SetNickname,
    SetPresence, SignedDeviceList, SignedUrl, Space, SpacePublicInfo, Thread, UpdateChannel,
    UpdateProfile, UpdateRole, UpdateSpace, UpdateThread, UploadAttachmentRequest,
    UploadImageRequest, UploadSlot, Welcome, emoji_ref, redeem, welcome,
};

/// Stands in for a redacted value: shows only how long it was.
struct Redacted(usize);

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} bytes>", self.0)
    }
}

fn redacted<T: AsRef<[u8]>>(value: &Option<T>) -> Option<Redacted> {
    value.as_ref().map(|v| Redacted(v.as_ref().len()))
}

/// An enum value as received: a value from a newer peer shows as its number.
struct Enum<E>(i32, PhantomData<E>);

fn known<E>(value: i32) -> Enum<E> {
    Enum(value, PhantomData)
}

impl<E: TryFrom<i32> + fmt::Debug> fmt::Debug for Enum<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match E::try_from(self.0) {
            Ok(value) => value.fmt(f),
            Err(_) => write!(f, "Unknown({})", self.0),
        }
    }
}

/// `Debug` for a message, naming every field (no `..`, so a new field is a
/// compile error here): `text` shows a string or bytes field's length only,
/// `opt_text` the same for an optional one, `kind` a `ChannelKind`, `purpose`
/// an `ImagePurpose`, and a bare field prints as it is.
macro_rules! redacting_debug {
    ($message:ident { $($field:ident $(: $how:ident)?),* $(,)? }) => {
        impl fmt::Debug for $message {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let Self { $($field),* } = self;
                f.debug_struct(stringify!($message))
                    $(.field(stringify!($field), &redacting_debug!(@show $field $($how)?)))*
                    .finish()
            }
        }
    };
    (@show $field:ident) => { $field };
    (@show $field:ident text) => { Redacted($field.len()) };
    (@show $field:ident opt_text) => { redacted($field) };
    (@show $field:ident kind) => { known::<ChannelKind>(*$field) };
    (@show $field:ident purpose) => { known::<ImagePurpose>(*$field) };
}

// A decoded Error's text comes from the peer, not from `Error::new`'s
// `&'static str`: it is redacted like any other peer text.
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            code,
            message,
            retry_after_ms,
            device_list,
        } = self;
        f.debug_struct("Error")
            .field("code", &known::<ErrorCode>(*code))
            .field("message", &Redacted(message.len()))
            .field("retry_after_ms", retry_after_ms)
            .field("device_list", device_list)
            .finish()
    }
}

impl fmt::Debug for SignedDeviceList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { body, signature } = self;
        f.debug_struct("SignedDeviceList")
            .field("body", &Redacted(body.len()))
            .field("signature", signature)
            .finish()
    }
}

impl fmt::Debug for Resume {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { token, last_seq } = self;
        f.debug_struct("Resume")
            .field("token", &Redacted(token.len()))
            .field("last_seq", last_seq)
            .finish()
    }
}

impl fmt::Debug for Welcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            session_id,
            account_id,
            membership,
            resume_token,
            device_list,
            state,
        } = self;
        f.debug_struct("Welcome")
            .field("session_id", session_id)
            .field("account_id", account_id)
            .field("membership", membership)
            .field("resume_token", &redacted(resume_token))
            .field("device_list", device_list)
            .field("state", state)
            .finish()
    }
}

impl fmt::Debug for welcome::State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Snapshot(snapshot) => f.debug_tuple("Snapshot").field(snapshot).finish(),
            Self::Resumed(resumed) => f.debug_tuple("Resumed").field(resumed).finish(),
        }
    }
}

impl fmt::Debug for ClientInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { name, version } = self;
        f.debug_struct("ClientInfo")
            .field("name", &Redacted(name.len()))
            .field("version", &Redacted(version.len()))
            .finish()
    }
}

impl fmt::Debug for PresenceUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            account_id,
            status,
            custom_status,
        } = self;
        f.debug_struct("PresenceUpdate")
            .field("account_id", account_id)
            .field("status", &known::<PresenceStatus>(*status))
            .field("custom_status", &Redacted(custom_status.len()))
            .finish()
    }
}

impl fmt::Debug for SetPresence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            status,
            afk,
            custom_status,
        } = self;
        f.debug_struct("SetPresence")
            .field("status", &status.map(known::<PresenceStatus>))
            .field("afk", afk)
            .field("custom_status", &redacted(custom_status))
            .finish()
    }
}

// M2 (§ 6.8): names, profiles and blobs are user content; redeem codes,
// invite codes and channel passwords are secrets.

redacting_debug!(SpacePublicInfo {
    name: text,
    description: text,
    rules: text,
    icon_id,
    claimed
});
redacting_debug!(Space {
    owner_account_id,
    name: text,
    description: text,
    rules: text,
    icon_id
});
redacting_debug!(Channel {
    id,
    kind: kind,
    parent_id,
    position,
    name: text,
    topic: text,
    slowmode_secs,
    max_members,
    has_password,
    age_restricted,
    needed_talk_power,
    max_bitrate,
    overwrites,
    retention_days,
    no_history,
    temporary,
});
redacting_debug!(Role {
    id,
    name: text,
    color,
    position,
    hoist,
    permissions,
    talk_power
});
redacting_debug!(Member {
    account_id,
    joined_at,
    nickname: opt_text,
    role_ids,
    display_name: text,
    avatar_id,
    bio: text,
    pronouns: text,
});
redacting_debug!(BlobData {
    blob_id,
    media_type: text,
    data: text
});
redacting_debug!(UpdateSpace {
    name: opt_text,
    description: opt_text,
    rules: opt_text
});
redacting_debug!(CreateChannel {
    kind: kind,
    parent_id,
    position,
    name: text,
    topic: opt_text,
    slowmode_secs,
    max_members,
    age_restricted,
    needed_talk_power,
    max_bitrate,
    retention_days,
    no_history,
    temporary,
});
redacting_debug!(UpdateChannel {
    channel_id,
    name: opt_text,
    topic: opt_text,
    slowmode_secs,
    max_members,
    age_restricted,
    needed_talk_power,
    max_bitrate,
    retention_days,
    no_history,
});
redacting_debug!(SetChannelPassword {
    channel_id,
    password: opt_text
});
redacting_debug!(JoinVoice {
    channel_id,
    password: opt_text
});
redacting_debug!(CreateRole {
    name: text,
    color,
    hoist,
    permissions,
    talk_power
});
redacting_debug!(UpdateRole {
    role_id,
    name: opt_text,
    color,
    hoist,
    permissions,
    talk_power
});
redacting_debug!(UpdateProfile {
    display_name: opt_text,
    bio: opt_text,
    pronouns: opt_text
});
redacting_debug!(SetNickname {
    account_id,
    nickname: opt_text
});
redacting_debug!(InviteCreated { invite, code: text });
redacting_debug!(UploadImageRequest {
    data: text,
    purpose: purpose
});
redacting_debug!(Redeem { code });

impl fmt::Debug for redeem::Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (name, code) = match self {
            Self::ClaimCode(code) => ("ClaimCode", code),
            Self::InviteCode(code) => ("InviteCode", code),
        };
        f.debug_tuple(name).field(&Redacted(code.len())).finish()
    }
}

// M3 (§ 6.9): message text, thread and emoji names, Unicode reactions, search
// queries, poke text and attachment bytes are user content; signed file URLs
// are secrets until they expire.

redacting_debug!(Message {
    id,
    channel_id,
    thread_id,
    author_id,
    created_at,
    content: text,
    reply_to,
    mentions,
    attachments,
    reactions,
    edited_at,
    deleted,
    pinned,
});
redacting_debug!(EmojiRef { emoji });

impl fmt::Debug for emoji_ref::Emoji {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unicode(text) => f
                .debug_tuple("Unicode")
                .field(&Redacted(text.len()))
                .finish(),
            Self::CustomId(id) => f.debug_tuple("CustomId").field(id).finish(),
        }
    }
}

redacting_debug!(Thread {
    id,
    channel_id,
    name: text,
    archived,
    created_by,
    created_at
});
redacting_debug!(CustomEmoji {
    id,
    name: text,
    image_id,
    created_by
});
redacting_debug!(SendMessage {
    channel_id,
    thread_id,
    content: text,
    reply_to,
    attachment_ids
});
redacting_debug!(EditMessage {
    message_id,
    content: text
});
redacting_debug!(CreateThread {
    message_id,
    name: text
});
redacting_debug!(UpdateThread {
    thread_id,
    name: opt_text,
    archived
});
redacting_debug!(PokeMember {
    account_id,
    text: opt_text
});
redacting_debug!(CreateEmoji {
    name: text,
    image_id
});
redacting_debug!(RenameEmoji {
    emoji_id,
    name: text
});
redacting_debug!(SearchRequest {
    query: text,
    before_id,
    limit
});
redacting_debug!(UploadAttachmentRequest { data: text });
redacting_debug!(SignedUrl {
    url: text,
    expires_at
});
redacting_debug!(UploadSlot {
    attachment_id,
    url: text,
    expires_at
});
redacting_debug!(Poke {
    from_account_id,
    text: text
});
