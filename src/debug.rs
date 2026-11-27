//! `Debug` for the messages that carry a secret (resume tokens, redeem codes,
//! channel passwords), user text (client info, custom status, names, profiles)
//! or other bytes a peer fills freely (error text, signed device-list bodies,
//! blobs): the shape and lengths only. PROTOCOL § 6.2
//! and § 6.3 say these are never logged; this keeps a stray `{:?}` from doing so.
//!
//! The messages are listed in `redacted_debug.txt` (read by build.rs), and
//! `tests/wire_surface.rs` fails on any text field that is neither redacted nor
//! listed as public. Each impl destructures its message without `..`, so a new
//! field is a compile error here rather than a silent omission.

use std::fmt;
use std::marker::PhantomData;

use crate::v1::{
    AccountDeviceList, ClaimKeyPackagesRequest, ClaimedKeyPackage, DeviceListsRequest,
    DmEncryption, DmMessageKind, MlsCommit, MlsEntry, MlsRejoinReason, MlsRejoinRequested,
    PublishKeyPackages, RequestMlsRejoin, ReserveDm, mls_entry,
};
use crate::v1::{
    AddDmMember, Block, BlockUpdated, CreateGroupDm, Dm, DmKind, DmReactionAdded,
    DmReactionRemoved, EditDmMessage, NotificationSetting, NotifyLevel, NotifyTarget, OpenDm,
    PersonalSnapshot, RelayTarget, RemoveDmMember, SendDmMessage, StartTyping, Typing, Unblock,
    UpdateDm, WebPushTarget,
};
use crate::v1::{
    AnswerMedia, BlobData, Channel, ChannelKind, ClientInfo, CreateChannel, CreateEmoji,
    CreateRole, CreateThread, CustomEmoji, DmMode, EditMessage, EmojiRef, Error, ErrorCode,
    ImagePurpose, InviteCreated, JoinPolicy, JoinVoice, Member, Message, Poke, PokeMember,
    PresenceStatus, PresenceUpdate, Redeem, RenameEmoji, Resume, Role, SearchRequest, SendMessage,
    SetChannelPassword, SetNickname, SetPresence, SignedDeviceList, SignedUrl, Space,
    SpacePublicInfo, SpaceStyle, Thread, UpdateChannel, UpdateProfile, UpdateRole, UpdateSpace,
    UpdateThread, UploadAttachmentRequest, UploadImageRequest, UploadSlot, VoiceChatAccess,
    Welcome, emoji_ref, redeem, welcome,
};
use crate::v1::{Bot, BotCreated, BotCredential, CreateBot};
use crate::v1::{
    CommandOption, CommandOptionKind, CommandOptionValue, CreateWebhook, Interaction,
    InvokeCommand, SlashCommand, Webhook, WebhookCreated, command_option_value,
};
use crate::v1::{
    DmContent, DmDelete, DmEdit, DmGroupName, DmReaction, DmText, EncryptedAttachment,
    EncryptedThumbnail, dm_content,
};
use crate::v1::{MediaKind, MediaOffer, MediaPublished, PublishMedia, TurnCredentials};

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

/// An id that would say who DMs, blocks or mutes whom next to the account a
/// frame belongs to (§ 6.17 "Content in logs"): never printed.
struct Hidden;

impl fmt::Debug for Hidden {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<hidden>")
    }
}

/// Stands in for a list of account ids (DM members, blocked accounts): their
/// number only.
struct Ids(usize);

impl fmt::Debug for Ids {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} ids>", self.0)
    }
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
/// an `ImagePurpose`, `style` / `access` a `SpaceStyle` / `VoiceChatAccess`
/// (`opt_style` / `opt_access` the optional ones), `option_kind` a
/// `CommandOptionKind`, `command_name` a command or option name only when it
/// has § 6.15's form (1–32 bytes of `a`–`z`, `0`–`9`, `_`, `-`; otherwise its
/// length), `count` a list by its length (option values), and a bare field
/// prints as it is.
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
    (@show $field:ident style) => { known::<SpaceStyle>(*$field) };
    (@show $field:ident access) => { known::<VoiceChatAccess>(*$field) };
    (@show $field:ident opt_style) => { $field.map(known::<SpaceStyle>) };
    (@show $field:ident opt_access) => { $field.map(known::<VoiceChatAccess>) };
    (@show $field:ident policy) => { known::<JoinPolicy>(*$field) };
    (@show $field:ident opt_policy) => { $field.map(known::<JoinPolicy>) };
    (@show $field:ident media) => { known::<MediaKind>(*$field) };
    (@show $field:ident texts) => { $field.iter().map(|t| Redacted(t.len())).collect::<Vec<_>>() };
    (@show $field:ident option_kind) => { known::<CommandOptionKind>(*$field) };
    (@show $field:ident command_name) => { CommandName($field) };
    (@show $field:ident count) => { Count($field.len()) };
    (@show $field:ident hidden) => { { let _ = $field; Hidden } };
    (@show $field:ident opt_hidden) => { $field.map(|_| Hidden) };
    (@show $field:ident ids) => { Ids($field.len()) };
    (@show $field:ident dm_kind) => { known::<DmKind>(*$field) };
    (@show $field:ident dm_mode) => { known::<DmMode>(*$field) };
    (@show $field:ident dm_encryption) => { known::<DmEncryption>(*$field) };
    (@show $field:ident dm_message_kind) => { known::<DmMessageKind>(*$field) };
    (@show $field:ident rejoin_reason) => { known::<MlsRejoinReason>(*$field) };
    (@show $field:ident notify_target) => { known::<NotifyTarget>(*$field) };
    (@show $field:ident notify_level) => { known::<NotifyLevel>(*$field) };
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
            mls_epoch,
        } = self;
        f.debug_struct("Error")
            .field("code", &known::<ErrorCode>(*code))
            .field("message", &Redacted(message.len()))
            .field("retry_after_ms", retry_after_ms)
            .field("device_list", device_list)
            .field("mls_epoch", mls_epoch)
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
        let Self {
            token,
            last_seq,
            personal_last_seq,
        } = self;
        f.debug_struct("Resume")
            .field("token", &Redacted(token.len()))
            .field("last_seq", last_seq)
            .field("personal_last_seq", personal_last_seq)
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
            push_info,
            mls_external_sender,
        } = self;
        f.debug_struct("Welcome")
            .field("session_id", session_id)
            .field("account_id", account_id)
            .field("membership", membership)
            .field("resume_token", &redacted(resume_token))
            .field("device_list", device_list)
            .field("state", state)
            .field("push_info", push_info)
            .field("mls_external_sender", mls_external_sender)
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
    claimed,
    style: style,
    join_policy: policy,
});
redacting_debug!(Space {
    owner_account_id,
    name: text,
    description: text,
    rules: text,
    icon_id,
    style: style,
    lobby_on_connect,
    threads,
    reactions,
    member_list,
    voice_chat_access: access,
    default_voice_channel,
    join_policy: policy,
    open_join_role_ids,
    dm_mode: dm_mode,
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
    timeout_until,
    bot,
});
redacting_debug!(BlobData {
    blob_id,
    media_type: text,
    data: text
});
redacting_debug!(UpdateSpace {
    name: opt_text,
    description: opt_text,
    rules: opt_text,
    style: opt_style,
    lobby_on_connect,
    threads,
    reactions,
    member_list,
    voice_chat_access: opt_access,
    default_voice_channel,
    join_policy: opt_policy,
    open_join_role_ids,
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
            // No secret: OpenJoin is empty (§ 6.14).
            Self::OpenJoin(open) => return f.debug_tuple("OpenJoin").field(open).finish(),
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
    webhook_id,
    webhook_name: opt_text,
    dm_id: opt_hidden,
    ciphertext: text,
    dm_kind: dm_message_kind,
    mls_epoch,
    delete_id,
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
// M10 (§ 6.17, § 6.18): DM text and names, who is in a DM, who blocks or
// mutes whom, and push secrets (§ 6.18 "Secrets and logs").
redacting_debug!(Dm {
    id,
    kind: dm_kind,
    member_ids: ids,
    name: text,
    owner_id: hidden,
    created_at,
    encryption: dm_encryption,
    successor_dm_id,
    mls_group_id: text,
});
redacting_debug!(CreateGroupDm {
    account_ids: ids,
    name: opt_text,
    reserved_dm_id,
    commit,
});
redacting_debug!(UpdateDm { dm_id, name: text });
redacting_debug!(SendDmMessage {
    dm_id,
    content: text,
    reply_to,
    attachment_ids,
    ciphertext: text,
    kind: dm_message_kind,
    delete_id,
});
redacting_debug!(EditDmMessage {
    dm_id,
    message_id,
    content: text,
});
redacting_debug!(BlockUpdated {
    account_id: hidden,
    blocked,
});
redacting_debug!(NotificationSetting {
    target: notify_target,
    target_id: hidden,
    level: notify_level,
    muted_until,
});
redacting_debug!(PersonalSnapshot {
    seq,
    dms,
    dm_read_states,
    blocked_account_ids: ids,
    notification_settings,
});
redacting_debug!(WebPushTarget {
    endpoint: text,
    p256dh: text,
    auth: text,
});
redacting_debug!(RelayTarget { token: text });
redacting_debug!(OpenDm {
    account_id: hidden,
    reserved_dm_id,
    commit,
});
redacting_debug!(AddDmMember {
    dm_id,
    account_id: hidden,
    commit,
});
// Minor 11 (§ 6.19): MLS message bytes, KeyPackages, and the targets of
// device-list lookups and claims never reach a log.
redacting_debug!(MlsCommit {
    epoch,
    commit: text,
    proposals: texts,
    welcome: opt_text,
    group_context: text,
});
redacting_debug!(ReserveDm {
    kind: dm_kind,
    account_ids: ids,
});
redacting_debug!(PublishKeyPackages {
    key_packages: texts,
    last_resort: opt_text,
});
redacting_debug!(DeviceListsRequest { account_ids: ids });
redacting_debug!(AccountDeviceList {
    account_id: hidden,
    account_pub,
    device_list,
});
redacting_debug!(ClaimKeyPackagesRequest { account_id: hidden });
redacting_debug!(ClaimedKeyPackage {
    device_pub,
    key_package: text,
    last_resort,
});
redacting_debug!(MlsEntry {
    dm_id,
    position,
    epoch,
    entry,
});

impl fmt::Debug for mls_entry::Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handshake(b) => f
                .debug_tuple("Handshake")
                .field(&Redacted(b.len()))
                .finish(),
            Self::Message(m) => f.debug_tuple("Message").field(m).finish(),
            Self::Welcome(b) => f.debug_tuple("Welcome").field(&Redacted(b.len())).finish(),
            Self::UpdateRequested(_) => f.write_str("UpdateRequested"),
            Self::RejoinRequested(r) => f.debug_tuple("RejoinRequested").field(r).finish(),
        }
    }
}
// § 6.19 "Content": what an MLS DM's ciphertext carries is content
// through and through: its ids, text, keys, digests, names and types are
// shown by length only, its mentions by count, and a file's size not at
// all (the server sees only the padded upload).
redacting_debug!(DmContent { id: text, body });

impl fmt::Debug for dm_content::Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(b) => f.debug_tuple("Text").field(b).finish(),
            Self::Edit(b) => f.debug_tuple("Edit").field(b).finish(),
            Self::Delete(b) => f.debug_tuple("Delete").field(b).finish(),
            Self::Reaction(b) => f.debug_tuple("Reaction").field(b).finish(),
            Self::GroupName(b) => f.debug_tuple("GroupName").field(b).finish(),
        }
    }
}
redacting_debug!(DmText {
    text: text,
    reply_to: opt_text,
    attachments,
    mentions: ids,
});
redacting_debug!(DmEdit {
    target: text,
    text: text,
});
redacting_debug!(DmDelete { target: text });
// Which emoji was reacted with is content too: its kind only.
impl fmt::Debug for DmReaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { target, emoji, on } = self;
        let kind = emoji.as_ref().map(|e| match e.emoji {
            Some(emoji_ref::Emoji::Unicode(_)) => "unicode",
            Some(emoji_ref::Emoji::CustomId(_)) => "custom",
            None => "unknown",
        });
        f.debug_struct("DmReaction")
            .field("target", &Redacted(target.len()))
            .field("emoji", &kind)
            .field("on", on)
            .finish()
    }
}
redacting_debug!(DmGroupName { name: text });
redacting_debug!(EncryptedAttachment {
    attachment_id,
    key: text,
    digest: text,
    name: text,
    mime: text,
    size: hidden,
    thumbnail,
});
redacting_debug!(EncryptedThumbnail {
    attachment_id,
    key: text,
    digest: text,
    mime: text,
    size: hidden,
});
// § 6.19 "Rejoining": the KeyPackage by length only, and who asks (a
// device of an account, next to its DM) never.
redacting_debug!(RequestMlsRejoin {
    dm_id,
    key_package: text,
    reason: rejoin_reason,
});
redacting_debug!(MlsRejoinRequested {
    account_id: hidden,
    device_pub: hidden,
    key_package: text,
    reason: rejoin_reason,
});
redacting_debug!(RemoveDmMember {
    dm_id,
    account_id: hidden,
});
redacting_debug!(Block { account_id: hidden });
redacting_debug!(Unblock { account_id: hidden });
redacting_debug!(DmReactionAdded {
    dm_id,
    message_id,
    emoji,
    account_id: hidden,
});
redacting_debug!(DmReactionRemoved {
    dm_id,
    message_id,
    emoji,
    account_id: hidden,
});
redacting_debug!(StartTyping {
    channel_id,
    thread_id,
    dm_id: opt_hidden,
});
redacting_debug!(Typing {
    channel_id,
    thread_id,
    account_id,
    dm_id: opt_hidden,
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
redacting_debug!(UploadAttachmentRequest {
    data: text,
    encrypted,
});
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

// M7 (§ 6.6): SDP carries addresses, ports, ICE credentials and the DTLS
// fingerprint; TURN credentials are secrets. Lengths only. The TURN URLs name
// the operator's TURN host, not a peer's, but are shown as lengths too: a
// stray `{:?}` has no use for them.
redacting_debug!(PublishMedia {
    kind: media,
    sdp_offer: text,
});
redacting_debug!(AnswerMedia {
    subscription_id,
    sdp_answer: text,
});
redacting_debug!(MediaPublished {
    media_id,
    sdp_answer: text,
});
redacting_debug!(MediaOffer {
    subscription_id,
    media_id,
    sdp_offer: text,
});
redacting_debug!(TurnCredentials {
    urls: texts,
    username: text,
    password: text,
    expires_at,
});

// M8 (§ 6.15): the seed is a secret shown once; a bot's name is user text;
// the key is public, the signature is shown by length only.
redacting_debug!(Bot {
    account_id,
    name: text,
    created_at,
    created_by,
});
redacting_debug!(BotCreated { bot, seed: text });
redacting_debug!(CreateBot { name: text });
redacting_debug!(BotCredential {
    bot_pub,
    signature: text
});

// M8 (§ 6.15): slash commands and webhooks. A webhook's token is a secret
// shown once; webhook names and command descriptions are user text. An
// invocation (`InvokeCommand`, `Interaction`, `CommandOptionValue`) shows ids,
// the command and option names and the number of options, never an option's
// value.

/// A command or option name: shown when it has the form § 6.15 allows (1-32
/// bytes of `a`-`z`, `0`-`9`, `_` and `-`), so a name that is not one (a
/// peer's free text in its place) shows by length only.
struct CommandName<'a>(&'a str);

impl fmt::Debug for CommandName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.0;
        let plain = (1..=32).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
        if plain {
            name.fmt(f)
        } else {
            Redacted(name.len()).fmt(f)
        }
    }
}

/// Stands in for a list whose entries are not shown: their number only.
struct Count(usize);

impl fmt::Debug for Count {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} options>", self.0)
    }
}

redacting_debug!(CommandOption {
    name: command_name,
    description: text,
    kind: option_kind,
    required,
});
redacting_debug!(SlashCommand {
    name: command_name,
    description: text,
    options,
});
redacting_debug!(Interaction {
    invoker_id,
    channel_id,
    name: command_name,
    options: count,
});
redacting_debug!(InvokeCommand {
    bot_account_id,
    channel_id,
    name: command_name,
    options: count,
});
redacting_debug!(Webhook {
    id,
    channel_id,
    name: text,
    created_by,
    created_at,
});
redacting_debug!(WebhookCreated {
    webhook,
    token: text
});
redacting_debug!(CreateWebhook {
    channel_id,
    name: text
});

/// The option's name and the kind of its value, never the value.
impl fmt::Debug for CommandOptionValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use command_option_value::Value;
        let Self { name, value } = self;
        let kind = value.as_ref().map(|value| match value {
            Value::Text(_) => "Text",
            Value::Integer(_) => "Integer",
            Value::Boolean(_) => "Boolean",
            Value::AccountId(_) => "AccountId",
            Value::ChannelId(_) => "ChannelId",
        });
        f.debug_struct("CommandOptionValue")
            .field("name", &CommandName(name))
            .field("value", &kind)
            .finish()
    }
}
