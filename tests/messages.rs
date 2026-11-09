//! Every message round-trips, and its bytes match a committed golden fixture
//! (`golden.txt`): a wire-stability guard beside `wire_surface.rs`. The client
//! and bot repos can check their encoders against the same fixtures.
//!
//! To update after an addition: `YAPSTA_BLESS=1 cargo test -p yapsta-proto --test messages`.

use prost::Message;
use yapsta_proto::v1::envelope::Body;
use yapsta_proto::v1::*;
use yapsta_proto::{ALPN, MINOR_VERSION, SUPPORTED_MINORS, WireCode};

const GOLDEN: &str = include_str!("golden.txt");

fn member() -> Member {
    Member {
        account_id: 42,
        joined_at: 1_800_000_000,
        ..Member::default()
    }
}

/// An M2 member, every field set; user text spelled so the Debug test can
/// look for it.
fn full_member() -> Member {
    Member {
        account_id: 43,
        joined_at: 1_800_000_001,
        nickname: Some("nick-text".to_owned()),
        role_ids: vec![2, 3],
        display_name: "display-text".to_owned(),
        avatar_id: Some(77),
        bio: "bio-text".to_owned(),
        pronouns: "pronoun-text".to_owned(),
        timeout_until: None,
    }
}

fn overwrite() -> Overwrite {
    Overwrite {
        channel_id: 5,
        target: Some(overwrite::Target::AccountId(43)),
        allow: Permission::Speak.bit().unwrap(),
        deny: Permission::Video.bit().unwrap(),
    }
}

fn channel() -> Channel {
    Channel {
        id: 5,
        kind: ChannelKind::Voice.into(),
        parent_id: Some(4),
        position: 1,
        name: "channel-text".to_owned(),
        topic: "topic-text".to_owned(),
        slowmode_secs: 0,
        max_members: 10,
        has_password: true,
        age_restricted: true,
        needed_talk_power: 50,
        max_bitrate: 64_000,
        overwrites: vec![overwrite()],
        retention_days: 0,
        no_history: false,
        temporary: false,
    }
}

fn space() -> Space {
    Space {
        owner_account_id: 42,
        name: "space-text".to_owned(),
        description: "description-text".to_owned(),
        rules: "rules-text".to_owned(),
        icon_id: Some(76),
        ..Space::default()
    }
}

fn invite() -> Invite {
    Invite {
        id: 9,
        created_by: 42,
        created_at: 1_800_000_002,
        expires_at: Some(1_800_086_402),
        max_uses: Some(5),
        uses: 1,
        role_ids: vec![2],
    }
}

/// M3 user text and secrets (§ 6.9), spelled so the Debug test can look for
/// them; the attachment bytes are 0xcd (205).
const M3_SECRETS: &[&str] = &[
    "message-text",
    "edit-text",
    "thread-text",
    "emoji-name-text",
    "unicode-text",
    "query-text",
    "poke-text",
    "https://url-text",
    "205, 205",
];

fn message() -> yapsta_proto::v1::Message {
    yapsta_proto::v1::Message {
        id: 70,
        channel_id: 5,
        thread_id: Some(69),
        author_id: 42,
        created_at: 1_800_000_100,
        content: "message-text".to_owned(),
        reply_to: Some(68),
        mentions: Some(Mentions {
            account_ids: vec![43],
            role_ids: vec![2],
            channel_ids: vec![5],
            everyone: true,
            here: false,
        }),
        attachments: vec![Attachment {
            id: 9,
            media_type: "image/webp".to_owned(),
            size: 2048,
            width: 640,
            height: 480,
            has_thumbnail: true,
        }],
        reactions: vec![ReactionCount {
            emoji: Some(unicode()),
            count: 2,
            me: true,
        }],
        edited_at: Some(1_800_000_200),
        deleted: false,
        pinned: true,
    }
}

fn unicode() -> EmojiRef {
    EmojiRef {
        emoji: Some(emoji_ref::Emoji::Unicode("unicode-text".to_owned())),
    }
}

fn custom() -> EmojiRef {
    EmojiRef {
        emoji: Some(emoji_ref::Emoji::CustomId(11)),
    }
}

fn thread() -> Thread {
    Thread {
        id: 69,
        channel_id: 5,
        name: "thread-text".to_owned(),
        archived: false,
        created_by: 42,
        created_at: 1_800_000_050,
    }
}

fn custom_emoji() -> CustomEmoji {
    CustomEmoji {
        id: 11,
        name: "emoji-name-text".to_owned(),
        image_id: 12,
        created_by: 42,
    }
}

fn read_state() -> ReadState {
    ReadState {
        channel_id: 5,
        last_read_id: 60,
        mention_count: 3,
        last_message_id: 70,
    }
}

/// The M3 examples (§ 6.9): one per new message, so every number is pinned
/// in `golden.txt` too.
fn m3_examples() -> Vec<(&'static str, Envelope)> {
    let env = |request_id, last, body| Envelope {
        request_id,
        last,
        body: Some(body),
    };
    let command = |kind| Body::Command(Command { kind: Some(kind) });
    let request = |kind| Body::Request(Request { kind: Some(kind) });
    let response = |kind| Body::Response(Response { kind: Some(kind) });
    let event = |kind| {
        Body::Event(Event {
            seq: 300,
            kind: Some(kind),
        })
    };
    let ephemeral = |kind| Body::Ephemeral(Ephemeral { kind: Some(kind) });
    use command::Kind as C;
    use event::Kind as E;
    use request::Kind as R;
    vec![
        (
            "m3_start_typing",
            env(
                0,
                false,
                Body::StartTyping(StartTyping {
                    channel_id: 5,
                    thread_id: Some(69),
                }),
            ),
        ),
        (
            "m3_send_message",
            env(
                30,
                false,
                command(C::SendMessage(SendMessage {
                    channel_id: 5,
                    thread_id: Some(69),
                    content: "message-text".to_owned(),
                    reply_to: Some(68),
                    attachment_ids: vec![9],
                })),
            ),
        ),
        (
            "m3_edit_message",
            env(
                31,
                false,
                command(C::EditMessage(EditMessage {
                    message_id: 70,
                    content: "edit-text".to_owned(),
                })),
            ),
        ),
        (
            "m3_delete_message",
            env(
                32,
                false,
                command(C::DeleteMessage(DeleteMessage { message_id: 70 })),
            ),
        ),
        (
            "m3_add_reaction",
            env(
                33,
                false,
                command(C::AddReaction(AddReaction {
                    message_id: 70,
                    emoji: Some(unicode()),
                })),
            ),
        ),
        (
            "m3_remove_reaction",
            env(
                34,
                false,
                command(C::RemoveReaction(RemoveReaction {
                    message_id: 70,
                    emoji: Some(custom()),
                    account_id: Some(43),
                })),
            ),
        ),
        (
            "m3_pin_message",
            env(
                35,
                false,
                command(C::PinMessage(PinMessage { message_id: 70 })),
            ),
        ),
        (
            "m3_unpin_message",
            env(
                36,
                false,
                command(C::UnpinMessage(UnpinMessage { message_id: 70 })),
            ),
        ),
        (
            "m3_create_thread",
            env(
                37,
                false,
                command(C::CreateThread(CreateThread {
                    message_id: 69,
                    name: "thread-text".to_owned(),
                })),
            ),
        ),
        (
            "m3_update_thread",
            env(
                38,
                false,
                command(C::UpdateThread(UpdateThread {
                    thread_id: 69,
                    name: Some("thread-text".to_owned()),
                    archived: Some(true),
                })),
            ),
        ),
        (
            "m3_mark_read",
            env(
                39,
                false,
                command(C::MarkRead(MarkRead {
                    channel_id: 5,
                    message_id: 70,
                })),
            ),
        ),
        (
            "m3_poke",
            env(
                40,
                false,
                command(C::Poke(PokeMember {
                    account_id: 43,
                    text: Some("poke-text".to_owned()),
                })),
            ),
        ),
        (
            "m3_create_emoji",
            env(
                41,
                false,
                command(C::CreateEmoji(CreateEmoji {
                    name: "emoji-name-text".to_owned(),
                    image_id: 12,
                })),
            ),
        ),
        (
            "m3_rename_emoji",
            env(
                42,
                false,
                command(C::RenameEmoji(RenameEmoji {
                    emoji_id: 11,
                    name: "emoji-name-text".to_owned(),
                })),
            ),
        ),
        (
            "m3_delete_emoji",
            env(
                43,
                false,
                command(C::DeleteEmoji(DeleteEmoji { emoji_id: 11 })),
            ),
        ),
        (
            "m3_message_history",
            env(
                50,
                false,
                request(R::MessageHistory(MessageHistoryRequest {
                    channel_id: 5,
                    thread_id: None,
                    anchor: Some(message_history_request::Anchor::Around(70)),
                    limit: 50,
                })),
            ),
        ),
        (
            "m3_get_messages",
            env(
                51,
                false,
                request(R::GetMessages(GetMessagesRequest {
                    message_ids: vec![68, 70],
                })),
            ),
        ),
        (
            "m3_list_pins",
            env(
                52,
                false,
                request(R::ListPins(ListPinsRequest { channel_id: 5 })),
            ),
        ),
        (
            "m3_list_threads",
            env(
                53,
                false,
                request(R::ListThreads(ListThreadsRequest {
                    channel_id: 5,
                    archived: true,
                    before_id: Some(80),
                    limit: 20,
                })),
            ),
        ),
        (
            "m3_search",
            env(
                54,
                false,
                request(R::Search(SearchRequest {
                    query: "query-text".to_owned(),
                    before_id: Some(80),
                    limit: 25,
                })),
            ),
        ),
        (
            "m3_upload_attachment",
            env(
                55,
                false,
                request(R::UploadAttachment(UploadAttachmentRequest {
                    data: vec![0xcd; 8],
                })),
            ),
        ),
        (
            "m3_fetch_attachment",
            env(
                56,
                false,
                request(R::FetchAttachment(FetchAttachmentRequest {
                    attachment_id: 9,
                    thumbnail: true,
                })),
            ),
        ),
        (
            "m3_attachment_url",
            env(
                57,
                false,
                request(R::AttachmentUrl(AttachmentUrlRequest {
                    attachment_id: 9,
                    thumbnail: false,
                })),
            ),
        ),
        (
            "m3_upload_url",
            env(
                58,
                false,
                request(R::UploadUrl(UploadUrlRequest { size: 10 << 20 })),
            ),
        ),
        (
            "m3_upload_emoji_image",
            env(
                59,
                false,
                request(R::UploadImage(UploadImageRequest {
                    data: vec![0xcd; 8],
                    purpose: ImagePurpose::Emoji.into(),
                })),
            ),
        ),
        (
            "m3_response_messages",
            env(
                50,
                true,
                response(response::Kind::Messages(MessageList {
                    messages: vec![message()],
                    has_more: true,
                })),
            ),
        ),
        (
            "m3_response_threads",
            env(
                53,
                true,
                response(response::Kind::Threads(ThreadList {
                    threads: vec![thread()],
                    has_more: false,
                })),
            ),
        ),
        (
            "m3_response_url",
            env(
                57,
                true,
                response(response::Kind::Url(SignedUrl {
                    url: "https://url-text".to_owned(),
                    expires_at: 1_800_000_600,
                })),
            ),
        ),
        (
            "m3_response_upload_slot",
            env(
                58,
                true,
                response(response::Kind::UploadSlot(UploadSlot {
                    attachment_id: 13,
                    url: "https://url-text".to_owned(),
                    expires_at: 1_800_000_600,
                })),
            ),
        ),
        (
            "m3_event_message_created",
            env(
                0,
                false,
                event(E::MessageCreated(MessageCreated {
                    message: Some(message()),
                })),
            ),
        ),
        (
            "m3_event_message_updated",
            env(
                0,
                false,
                event(E::MessageUpdated(MessageUpdated {
                    message: Some(message()),
                })),
            ),
        ),
        (
            "m3_event_message_deleted",
            env(
                0,
                false,
                event(E::MessageDeleted(MessageDeleted {
                    channel_id: 5,
                    message_id: 70,
                })),
            ),
        ),
        (
            "m3_event_reaction_added",
            env(
                0,
                false,
                event(E::ReactionAdded(ReactionAdded {
                    channel_id: 5,
                    message_id: 70,
                    emoji: Some(unicode()),
                    account_id: 43,
                })),
            ),
        ),
        (
            "m3_event_reaction_removed",
            env(
                0,
                false,
                event(E::ReactionRemoved(ReactionRemoved {
                    channel_id: 5,
                    message_id: 70,
                    emoji: Some(custom()),
                    account_id: 43,
                })),
            ),
        ),
        (
            "m3_event_message_pinned",
            env(
                0,
                false,
                event(E::MessagePinned(MessagePinned {
                    channel_id: 5,
                    message_id: 70,
                    pinned_by: 42,
                })),
            ),
        ),
        (
            "m3_event_message_unpinned",
            env(
                0,
                false,
                event(E::MessageUnpinned(MessageUnpinned {
                    channel_id: 5,
                    message_id: 70,
                })),
            ),
        ),
        (
            "m3_event_thread_created",
            env(
                0,
                false,
                event(E::ThreadCreated(ThreadCreated {
                    thread: Some(thread()),
                })),
            ),
        ),
        (
            "m3_event_thread_updated",
            env(
                0,
                false,
                event(E::ThreadUpdated(ThreadUpdated {
                    thread: Some(thread()),
                })),
            ),
        ),
        (
            "m3_event_emoji_created",
            env(
                0,
                false,
                event(E::EmojiCreated(EmojiCreated {
                    emoji: Some(custom_emoji()),
                })),
            ),
        ),
        (
            "m3_event_emoji_updated",
            env(
                0,
                false,
                event(E::EmojiUpdated(EmojiUpdated {
                    emoji: Some(custom_emoji()),
                })),
            ),
        ),
        (
            "m3_event_emoji_deleted",
            env(
                0,
                false,
                event(E::EmojiDeleted(EmojiDeleted { emoji_id: 11 })),
            ),
        ),
        (
            "m3_ephemeral_typing",
            env(
                0,
                false,
                ephemeral(ephemeral::Kind::Typing(Typing {
                    channel_id: 5,
                    thread_id: None,
                    account_id: 43,
                })),
            ),
        ),
        (
            "m3_ephemeral_poke",
            env(
                0,
                false,
                ephemeral(ephemeral::Kind::Poke(Poke {
                    from_account_id: 42,
                    text: "poke-text".to_owned(),
                })),
            ),
        ),
        (
            "m3_ephemeral_read_state",
            env(
                0,
                false,
                ephemeral(ephemeral::Kind::ReadState(read_state())),
            ),
        ),
        (
            "m3_resync",
            env(
                0,
                false,
                Body::Resync(Snapshot {
                    seq: 301,
                    read_states: vec![read_state()],
                    emoji: vec![custom_emoji()],
                    channels: vec![Channel {
                        topic: String::new(),
                        retention_days: 30,
                        no_history: false,
                        ..channel()
                    }],
                    ..Snapshot::default()
                }),
            ),
        ),
        (
            "m3_welcome_resumed",
            env(
                0,
                false,
                Body::Welcome(Welcome {
                    session_id: 13,
                    account_id: Some(42),
                    membership: None,
                    resume_token: None,
                    device_list: None,
                    state: Some(welcome::State::Resumed(Resumed {
                        presences: vec![],
                        read_states: vec![read_state()],
                    })),
                }),
            ),
        ),
        (
            "m3_command_update_channel",
            env(
                60,
                false,
                command(C::UpdateChannel(UpdateChannel {
                    channel_id: 5,
                    retention_days: Some(7),
                    no_history: Some(true),
                    ..UpdateChannel::default()
                })),
            ),
        ),
    ]
}

/// Every user text, code and password the M2 examples carry.
const M2_SECRETS: &[&str] = &[
    "nick-text",
    "display-text",
    "bio-text",
    "pronoun-text",
    "channel-text",
    "topic-text",
    "space-text",
    "description-text",
    "rules-text",
    "role-text",
    "claim-code-text",
    "invite-code-text",
    "password-text",
    "image/png",
];

fn voice_state() -> VoiceState {
    VoiceState {
        account_id: 42,
        channel_id: 5,
        session_ref: 7,
        self_mute: true,
        self_deaf: false,
        server_mute: true,
        server_deaf: true,
        priority: true,
    }
}

/// One example of every M4 (§ 6.10) kind and field.
fn m4_examples() -> Vec<(&'static str, Envelope)> {
    let env = |request_id, body| Envelope {
        request_id,
        last: false,
        body: Some(body),
    };
    let command = |kind| Body::Command(Command { kind: Some(kind) });
    use command::Kind as C;
    vec![
        (
            "m4_join_voice",
            env(
                70,
                command(C::JoinVoice(JoinVoice {
                    channel_id: 5,
                    password: Some("voice-password-text".to_owned()),
                })),
            ),
        ),
        (
            "m4_leave_voice",
            env(71, command(C::LeaveVoice(LeaveVoice {}))),
        ),
        (
            "m4_set_voice_state",
            env(
                72,
                command(C::SetVoiceState(SetVoiceState {
                    self_mute: Some(true),
                    self_deaf: Some(false),
                    priority: Some(true),
                })),
            ),
        ),
        (
            "m4_set_member_voice",
            env(
                73,
                command(C::SetMemberVoice(SetMemberVoice {
                    account_id: 43,
                    server_mute: Some(true),
                    server_deaf: Some(false),
                })),
            ),
        ),
        (
            "m4_move_member",
            env(
                74,
                command(C::MoveMember(MoveMember {
                    account_id: 43,
                    channel_id: 6,
                })),
            ),
        ),
        (
            "m4_disconnect_member",
            env(
                75,
                command(C::DisconnectMember(DisconnectMember { account_id: 43 })),
            ),
        ),
        (
            "m4_set_whisper_list",
            env(
                76,
                command(C::SetWhisperList(SetWhisperList {
                    list_id: 8,
                    account_ids: vec![43, 44],
                    channel_ids: vec![6],
                    role_ids: vec![2],
                })),
            ),
        ),
        (
            "m4_clear_whisper_list",
            env(
                77,
                command(C::ClearWhisperList(ClearWhisperList { list_id: 8 })),
            ),
        ),
        (
            "m4_create_temporary_channel",
            env(
                78,
                command(C::CreateChannel(CreateChannel {
                    kind: ChannelKind::Voice.into(),
                    name: "channel-text".to_owned(),
                    temporary: Some(true),
                    ..CreateChannel::default()
                })),
            ),
        ),
        (
            "m4_event_voice_state_updated",
            env(
                0,
                Body::Event(Event {
                    seq: 400,
                    kind: Some(event::Kind::VoiceStateUpdated(VoiceStateUpdated {
                        state: Some(voice_state()),
                        previous_channel_id: 6,
                    })),
                }),
            ),
        ),
        (
            "m4_event_temporary_channel_created",
            env(
                0,
                Body::Event(Event {
                    seq: 401,
                    kind: Some(event::Kind::ChannelCreated(ChannelCreated {
                        channel: Some(Channel {
                            temporary: true,
                            overwrites: vec![],
                            ..channel()
                        }),
                    })),
                }),
            ),
        ),
        (
            "m4_ephemeral_voice_session",
            env(
                0,
                Body::Ephemeral(Ephemeral {
                    kind: Some(ephemeral::Kind::VoiceSession(VoiceSession {
                        session_ref: 7,
                        channel_id: 5,
                    })),
                }),
            ),
        ),
        (
            "m4_resync_voice_states",
            env(
                0,
                Body::Resync(Snapshot {
                    seq: 402,
                    voice_states: vec![voice_state()],
                    ..Snapshot::default()
                }),
            ),
        ),
    ]
}

/// M5 (§ 6.11): the space style, its switches and starter templates.
fn m5_examples() -> Vec<(&'static str, Envelope)> {
    use command::Kind as C;
    let env = |request_id, body| Envelope {
        request_id,
        last: false,
        body: Some(body),
    };
    let command = |kind| Body::Command(Command { kind: Some(kind) });
    vec![
        (
            "m5_apply_template",
            env(
                80,
                command(C::ApplyTemplate(ApplyTemplate {
                    template: StarterTemplate::Gaming.into(),
                })),
            ),
        ),
        (
            "m5_update_space",
            env(
                81,
                command(C::UpdateSpace(UpdateSpace {
                    style: Some(SpaceStyle::VoiceFirst.into()),
                    lobby_on_connect: Some(true),
                    threads: Some(false),
                    reactions: Some(true),
                    member_list: Some(false),
                    voice_chat_access: Some(VoiceChatAccess::MembersInChannel.into()),
                    default_voice_channel: Some(6),
                    ..UpdateSpace::default()
                })),
            ),
        ),
        (
            "m5_event_space_updated",
            env(
                0,
                Body::Event(Event {
                    seq: 500,
                    kind: Some(event::Kind::SpaceUpdated(SpaceUpdated {
                        space: Some(Space {
                            style: SpaceStyle::TextFirst.into(),
                            lobby_on_connect: false,
                            threads: true,
                            reactions: true,
                            member_list: true,
                            voice_chat_access: VoiceChatAccess::ChannelViewers.into(),
                            default_voice_channel: Some(6),
                            ..space()
                        }),
                    })),
                }),
            ),
        ),
        (
            "m5_hello",
            env(
                0,
                Body::Hello(Hello {
                    server_id: "a5jy5opmsxgrcsn22buvxzm5qi".to_owned(),
                    versions: vec![5, 4],
                    challenge: vec![1; 32],
                    capabilities: vec![],
                    space_public_info: Some(SpacePublicInfo {
                        name: "space-text".to_owned(),
                        claimed: true,
                        style: SpaceStyle::VoiceFirst.into(),
                        ..SpacePublicInfo::default()
                    }),
                }),
            ),
        ),
    ]
}

/// M7 (§ 6.14): open join. The redeem variant, the `update_space` fields,
/// and the policy in `Space` and `SpacePublicInfo`.
fn m7_examples() -> Vec<(&'static str, Envelope)> {
    use command::Kind as C;
    let env = |request_id, body| Envelope {
        request_id,
        last: false,
        body: Some(body),
    };
    vec![
        (
            "m7_redeem_open_join",
            env(
                100,
                Body::Redeem(Redeem {
                    code: Some(redeem::Code::OpenJoin(OpenJoin {})),
                }),
            ),
        ),
        (
            "m7_update_space",
            env(
                101,
                Body::Command(Command {
                    kind: Some(C::UpdateSpace(UpdateSpace {
                        join_policy: Some(JoinPolicy::Open.into()),
                        open_join_role_ids: Some(RoleIdList {
                            role_ids: vec![2, 3],
                        }),
                        ..UpdateSpace::default()
                    })),
                }),
            ),
        ),
        (
            "m7_update_space_no_roles",
            env(
                102,
                Body::Command(Command {
                    kind: Some(C::UpdateSpace(UpdateSpace {
                        open_join_role_ids: Some(RoleIdList { role_ids: vec![] }),
                        ..UpdateSpace::default()
                    })),
                }),
            ),
        ),
        (
            "m7_event_space_updated",
            env(
                0,
                Body::Event(Event {
                    seq: 700,
                    kind: Some(event::Kind::SpaceUpdated(SpaceUpdated {
                        space: Some(Space {
                            join_policy: JoinPolicy::Open.into(),
                            open_join_role_ids: vec![2, 3],
                            ..space()
                        }),
                    })),
                }),
            ),
        ),
        (
            "m7_hello",
            env(
                0,
                Body::Hello(Hello {
                    server_id: "a5jy5opmsxgrcsn22buvxzm5qi".to_owned(),
                    versions: vec![7, 6],
                    challenge: vec![1; 32],
                    capabilities: vec![],
                    space_public_info: Some(SpacePublicInfo {
                        name: "space-text".to_owned(),
                        claimed: true,
                        join_policy: JoinPolicy::Open.into(),
                        ..SpacePublicInfo::default()
                    }),
                }),
            ),
        ),
    ]
}

/// M6 (§ 6.12): moderation commands, the audit and ban pages, and the fields
/// M6 adds to `Member` and `MemberRemoved`.
fn m6_examples() -> Vec<(&'static str, Envelope)> {
    use command::Kind as C;
    use request::Kind as R;
    let env = |request_id, last, body| Envelope {
        request_id,
        last,
        body: Some(body),
    };
    let command = |kind| Body::Command(Command { kind: Some(kind) });
    let request = |kind| Body::Request(Request { kind: Some(kind) });
    let response = |kind| Body::Response(Response { kind: Some(kind) });
    vec![
        (
            "m6_kick_member",
            env(
                90,
                false,
                command(C::KickMember(KickMember { account_id: 43 })),
            ),
        ),
        (
            "m6_ban_member",
            env(
                91,
                false,
                command(C::BanMember(BanMember { account_id: 43 })),
            ),
        ),
        (
            "m6_unban_member",
            env(
                92,
                false,
                command(C::UnbanMember(UnbanMember { account_id: 43 })),
            ),
        ),
        (
            "m6_timeout_member",
            env(
                93,
                false,
                command(C::TimeoutMember(TimeoutMember {
                    account_id: 43,
                    until: Some(1_800_003_600),
                })),
            ),
        ),
        (
            "m6_timeout_member_clear",
            env(
                94,
                false,
                command(C::TimeoutMember(TimeoutMember {
                    account_id: 43,
                    until: None,
                })),
            ),
        ),
        (
            "m6_audit_page_request",
            env(
                95,
                false,
                request(R::AuditPage(AuditPageRequest {
                    before: Some(700),
                    limit: 50,
                    action: Some(AuditAction::Ban.into()),
                })),
            ),
        ),
        (
            "m6_ban_list_request",
            env(
                96,
                false,
                request(R::BanList(BanListRequest {
                    before: Some(44),
                    limit: 100,
                })),
            ),
        ),
        (
            "m6_audit_page",
            env(
                95,
                true,
                response(response::Kind::AuditPage(AuditPage {
                    entries: vec![
                        AuditEntry {
                            id: 699,
                            at: 1_800_000_100,
                            actor_kind: ActorKind::Member.into(),
                            actor_account_id: Some(42),
                            action: AuditAction::TransferMember.into(),
                            target_account_id: Some(43),
                            other_account_id: Some(44),
                            value: None,
                        },
                        AuditEntry {
                            id: 698,
                            at: 1_800_000_050,
                            actor_kind: ActorKind::Operator.into(),
                            actor_account_id: None,
                            action: AuditAction::AdminTokenCreate.into(),
                            target_account_id: None,
                            other_account_id: None,
                            value: Some(0x8000_0000_0000_0001),
                        },
                    ],
                    has_more: true,
                })),
            ),
        ),
        (
            "m6_ban_page",
            env(
                96,
                true,
                response(response::Kind::BanPage(BanPage {
                    bans: vec![
                        Ban {
                            account_id: 43,
                            created_at: 1_800_000_200,
                        },
                        Ban {
                            account_id: 41,
                            created_at: 1_800_000_100,
                        },
                    ],
                    has_more: false,
                })),
            ),
        ),
        (
            "m6_event_member_updated_timeout",
            env(
                0,
                false,
                Body::Event(Event {
                    seq: 600,
                    kind: Some(event::Kind::MemberUpdated(MemberUpdated {
                        member: Some(Member {
                            timeout_until: Some(1_800_003_600),
                            ..full_member()
                        }),
                    })),
                }),
            ),
        ),
        (
            "m6_event_member_removed_banned",
            env(
                0,
                false,
                Body::Event(Event {
                    seq: 601,
                    kind: Some(event::Kind::MemberRemoved(MemberRemoved {
                        account_id: 43,
                        reason: MemberRemovedReason::Banned.into(),
                    })),
                }),
            ),
        ),
        (
            "m6_hello",
            env(
                0,
                false,
                Body::Hello(Hello {
                    server_id: "a5jy5opmsxgrcsn22buvxzm5qi".to_owned(),
                    versions: vec![6, 5],
                    challenge: vec![1; 32],
                    capabilities: vec![],
                    space_public_info: None,
                }),
            ),
        ),
    ]
}

fn presence() -> PresenceUpdate {
    PresenceUpdate {
        account_id: 42,
        status: PresenceStatus::Dnd.into(),
        custom_status: "away".to_owned(),
    }
}

fn device_list() -> SignedDeviceList {
    let body = DeviceListBody {
        version: 3,
        devices: vec![DeviceEntry {
            device_pub: vec![7; 32],
            expires_at: 1_807_776_000,
        }],
    };
    SignedDeviceList {
        body: body.encode_to_vec(),
        signature: vec![9; 64],
    }
}

/// One fully populated example per `Envelope` body.
fn examples() -> Vec<(&'static str, Envelope)> {
    let env = |request_id, last, body| Envelope {
        request_id,
        last,
        body: Some(body),
    };
    vec![
        (
            "error",
            env(
                5,
                true,
                Body::Error(Error {
                    retry_after_ms: Some(1500),
                    ..Error::new(ErrorCode::RateLimited, "slow down")
                }),
            ),
        ),
        (
            "hello",
            env(
                0,
                false,
                Body::Hello(Hello {
                    server_id: "a5jy5opmsxgrcsn22buvxzm5qi".to_owned(),
                    // Literal M1 values: these fixtures pin the M1 encoding.
                    versions: vec![1],
                    challenge: vec![1; 32],
                    capabilities: vec![Capability::Unspecified.into()],
                    space_public_info: Some(SpacePublicInfo::default()),
                }),
            ),
        ),
        (
            "auth",
            env(
                0,
                false,
                Body::Auth(Auth {
                    version: 1,
                    credential: Some(auth::Credential::Device(DeviceCredential {
                        account_pub: vec![2; 32],
                        device_list: Some(device_list()),
                        device_pub: vec![7; 32],
                        signature: vec![3; 64],
                    })),
                    capabilities: vec![],
                    client_info: Some(ClientInfo {
                        name: "yapsta-cli".to_owned(),
                        version: "0.1.0".to_owned(),
                    }),
                    presence: Some(PresenceStatus::Invisible.into()),
                    resume: Some(Resume {
                        token: vec![4; 32],
                        last_seq: 99,
                    }),
                }),
            ),
        ),
        (
            "welcome_snapshot",
            env(
                0,
                false,
                Body::Welcome(Welcome {
                    session_id: 11,
                    account_id: Some(42),
                    membership: Some(member()),
                    resume_token: Some(vec![5; 32]),
                    device_list: Some(device_list()),
                    state: Some(welcome::State::Snapshot(Snapshot {
                        seq: 100,
                        member: Some(member()),
                        presences: vec![presence()],
                        ..Snapshot::default()
                    })),
                }),
            ),
        ),
        (
            "welcome_resumed",
            env(
                0,
                false,
                Body::Welcome(Welcome {
                    session_id: 12,
                    account_id: None,
                    membership: None,
                    resume_token: None,
                    device_list: None,
                    state: Some(welcome::State::Resumed(Resumed {
                        presences: vec![presence()],
                        read_states: vec![],
                    })),
                }),
            ),
        ),
        (
            "event_member_joined",
            env(
                0,
                false,
                Body::Event(Event {
                    seq: 101,
                    kind: Some(event::Kind::MemberJoined(MemberJoined {
                        member: Some(member()),
                    })),
                }),
            ),
        ),
        (
            "ephemeral_presence",
            env(
                0,
                false,
                Body::Ephemeral(Ephemeral {
                    kind: Some(ephemeral::Kind::PresenceUpdate(presence())),
                }),
            ),
        ),
        (
            "set_presence",
            env(
                6,
                false,
                Body::SetPresence(SetPresence {
                    status: Some(PresenceStatus::Idle.into()),
                    afk: Some(true),
                    custom_status: Some(String::new()),
                }),
            ),
        ),
        ("ack", env(6, true, Body::Ack(Ack {}))),
        ("ping", env(7, false, Body::Ping(Ping {}))),
        // M2 (minor 2).
        (
            "hello_m2",
            env(
                0,
                false,
                Body::Hello(Hello {
                    server_id: "a5jy5opmsxgrcsn22buvxzm5qi".to_owned(),
                    versions: vec![2, 1], // An M2 server's Hello, as committed.
                    challenge: vec![1; 32],
                    capabilities: vec![],
                    space_public_info: Some(SpacePublicInfo {
                        name: "space-text".to_owned(),
                        description: "description-text".to_owned(),
                        rules: "rules-text".to_owned(),
                        icon_id: Some(76),
                        claimed: true,
                        ..SpacePublicInfo::default()
                    }),
                }),
            ),
        ),
        (
            "redeem_claim",
            env(
                8,
                false,
                Body::Redeem(Redeem {
                    code: Some(redeem::Code::ClaimCode("claim-code-text".to_owned())),
                }),
            ),
        ),
        (
            "redeem_invite",
            env(
                9,
                false,
                Body::Redeem(Redeem {
                    code: Some(redeem::Code::InviteCode("invite-code-text".to_owned())),
                }),
            ),
        ),
        (
            "resync",
            env(
                0,
                false,
                Body::Resync(Snapshot {
                    seq: 200,
                    member: Some(full_member()),
                    presences: vec![presence()],
                    space: Some(Space {
                        description: String::new(),
                        rules: String::new(),
                        ..space()
                    }),
                    channels: vec![Channel {
                        topic: String::new(),
                        ..channel()
                    }],
                    roles: vec![Role {
                        id: 2,
                        name: "role-text".to_owned(),
                        color: 0x00ff_8800,
                        position: 1,
                        hoist: true,
                        permissions: Permission::Administrator.bit().unwrap(),
                        talk_power: 100,
                    }],
                    members: vec![Member {
                        bio: String::new(),
                        pronouns: String::new(),
                        ..full_member()
                    }],
                    base_permissions: Permission::ViewChannel.bit().unwrap()
                        | Permission::CreateTempChannel.bit().unwrap(),
                    channel_permissions: vec![ChannelPermissions {
                        channel_id: 5,
                        permissions: u64::MAX,
                    }],
                    read_states: vec![],
                    emoji: vec![],
                    voice_states: vec![],
                }),
            ),
        ),
        (
            "command_create_channel",
            env(
                10,
                false,
                Body::Command(Command {
                    kind: Some(command::Kind::CreateChannel(CreateChannel {
                        kind: ChannelKind::Text.into(),
                        parent_id: Some(4),
                        position: Some(0),
                        name: "channel-text".to_owned(),
                        topic: Some("topic-text".to_owned()),
                        slowmode_secs: Some(30),
                        max_members: None,
                        age_restricted: Some(false),
                        needed_talk_power: None,
                        max_bitrate: None,
                        retention_days: None,
                        no_history: None,
                        temporary: None,
                    })),
                }),
            ),
        ),
        (
            "command_set_channel_password",
            env(
                11,
                false,
                Body::Command(Command {
                    kind: Some(command::Kind::SetChannelPassword(SetChannelPassword {
                        channel_id: 5,
                        password: Some("password-text".to_owned()),
                    })),
                }),
            ),
        ),
        (
            "command_delete_overwrite",
            env(
                12,
                false,
                Body::Command(Command {
                    kind: Some(command::Kind::DeleteOverwrite(DeleteOverwrite {
                        channel_id: 5,
                        target: Some(delete_overwrite::Target::RoleId(1)),
                    })),
                }),
            ),
        ),
        (
            "command_result_invite_created",
            env(
                13,
                true,
                Body::CommandResult(CommandResult {
                    kind: Some(command_result::Kind::InviteCreated(InviteCreated {
                        invite: Some(invite()),
                        code: "invite-code-text".to_owned(),
                    })),
                }),
            ),
        ),
        (
            "command_result_space",
            env(
                14,
                true,
                Body::CommandResult(CommandResult {
                    kind: Some(command_result::Kind::Space(space())),
                }),
            ),
        ),
        (
            "request_member_page",
            env(
                15,
                false,
                Body::Request(Request {
                    kind: Some(request::Kind::MemberPage(MemberPageRequest {
                        after_account_id: Some(42),
                        limit: 1000,
                    })),
                }),
            ),
        ),
        (
            "response_member_page",
            env(
                15,
                true,
                Body::Response(Response {
                    kind: Some(response::Kind::MemberPage(MemberPage {
                        members: vec![full_member()],
                        has_more: true,
                        presences: vec![presence()],
                    })),
                }),
            ),
        ),
        (
            "response_blob",
            env(
                16,
                true,
                Body::Response(Response {
                    kind: Some(response::Kind::Blob(BlobData {
                        blob_id: 76,
                        media_type: "image/png".to_owned(),
                        data: vec![0x89, 0x50, 0x4e, 0x47].into(),
                    })),
                }),
            ),
        ),
        (
            "event_channel_created",
            env(
                0,
                false,
                Body::Event(Event {
                    seq: 201,
                    kind: Some(event::Kind::ChannelCreated(ChannelCreated {
                        channel: Some(Channel {
                            overwrites: vec![],
                            ..channel()
                        }),
                    })),
                }),
            ),
        ),
        (
            "event_overwrite_deleted",
            env(
                0,
                false,
                Body::Event(Event {
                    seq: 202,
                    kind: Some(event::Kind::OverwriteDeleted(OverwriteDeleted {
                        channel_id: 5,
                        target: Some(overwrite_deleted::Target::AccountId(43)),
                    })),
                }),
            ),
        ),
        (
            "event_member_removed",
            env(
                0,
                false,
                Body::Event(Event {
                    seq: 203,
                    kind: Some(event::Kind::MemberRemoved(MemberRemoved {
                        account_id: 43,
                        ..MemberRemoved::default()
                    })),
                }),
            ),
        ),
        (
            "ephemeral_channel_permissions",
            env(
                0,
                false,
                Body::Ephemeral(Ephemeral {
                    kind: Some(ephemeral::Kind::ChannelPermissions(ChannelPermissions {
                        channel_id: 5,
                        permissions: Permission::ViewChannel.bit().unwrap(),
                    })),
                }),
            ),
        ),
    ]
    .into_iter()
    .chain(m3_examples())
    .chain(m4_examples())
    .chain(m5_examples())
    .chain(m6_examples())
    .chain(m7_examples())
    .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn golden(name: &str) -> Option<&'static str> {
    GOLDEN
        .lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(' '))
}

#[test]
fn every_message_round_trips_and_matches_its_golden_bytes() {
    let examples = examples();
    // A committed fixture never goes away: every one keeps its example.
    for line in GOLDEN.lines().filter(|l| !l.is_empty()) {
        let name = line.split(' ').next().unwrap();
        assert!(
            examples.iter().any(|(e, _)| *e == name),
            "the committed fixture {name} has no example any more"
        );
    }
    #[allow(
        clippy::disallowed_methods,
        reason = "a test-only switch to record new fixtures"
    )]
    if std::env::var_os("YAPSTA_BLESS").is_some() {
        // New fixtures only: a committed fixture never changes.
        for (name, env) in &examples {
            if let Some(bytes) = golden(name) {
                assert_eq!(hex(&env.encode_to_vec()), bytes, "{name} changed");
            }
        }
        let lines: Vec<String> = examples
            .iter()
            .map(|(name, env)| format!("{name} {}", hex(&env.encode_to_vec())))
            .collect();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden.txt");
        std::fs::write(path, lines.join("\n") + "\n").unwrap();
        return;
    }
    for (name, env) in examples {
        let bytes =
            golden(name).unwrap_or_else(|| panic!("no golden bytes for {name}; YAPSTA_BLESS=1"));
        // The fixtures are a decode contract for the client and bot repos...
        assert_eq!(
            Envelope::decode(unhex(bytes).as_slice()).unwrap(),
            env,
            "{name}: decode"
        );
        // ...and today's encoder still produces them.
        assert_eq!(
            hex(&env.encode_to_vec()),
            bytes,
            "{name}: the wire bytes changed"
        );
    }
}

#[test]
fn an_unknown_body_variant_decodes_to_none() {
    // A newer peer's body variant: field 99, length-delimited, 2 bytes.
    let mut bytes = Envelope {
        request_id: 3,
        last: false,
        body: None,
    }
    .encode_to_vec();
    bytes.extend_from_slice(&[0x9a, 0x06, 0x02, 0xaa, 0xbb]);
    let env = Envelope::decode(bytes.as_slice()).unwrap();
    assert_eq!(env.request_id, 3);
    assert_eq!(env.body, None);
}

#[test]
fn unknown_variants_inside_messages_decode_to_none() {
    // A newer peer's variant: field 99, length-delimited, 0 bytes.
    let unknown = [0x9a, 0x06, 0x00];
    let event = Event::decode([&[0x08, 0x05][..], &unknown].concat().as_slice()).unwrap();
    assert_eq!((event.seq, event.kind), (5, None));
    assert_eq!(Ephemeral::decode(&unknown[..]).unwrap().kind, None);
    let auth = Auth::decode([&[0x08, 0x01][..], &unknown].concat().as_slice()).unwrap();
    assert_eq!((auth.version, auth.credential), (1, None));
    assert_eq!(Welcome::decode(&unknown[..]).unwrap().state, None);
}

#[test]
fn the_constants() {
    assert_eq!(ALPN, b"yapsta/1");
    assert_eq!(MINOR_VERSION, 7);
    assert_eq!(SUPPORTED_MINORS, [7, 6]);
    assert_eq!(yapsta_proto::MAX_CONTROL_FRAME, 1 << 20);
    assert_eq!(yapsta_proto::MAX_REQUEST_FRAME, 16 << 20);
}

#[test]
fn debug_output_redacts_secrets_and_user_text() {
    let env = examples()
        .into_iter()
        .map(|(_, env)| format!("{env:?}"))
        .collect::<Vec<_>>()
        .join("\n");
    // The resume tokens (4s and 5s) and the user text never appear.
    assert!(!env.contains("[4, 4, 4"), "{env}");
    assert!(!env.contains("[5, 5, 5"), "{env}");
    for text in ["yapsta-cli", "0.1.0", "away"]
        .iter()
        .chain(M2_SECRETS)
        .chain(M3_SECRETS)
    {
        assert!(!env.contains(text), "{text} in {env}");
    }
    assert!(env.contains("<32 bytes>"), "{env}");
    // The blob's bytes (0x89 0x50 ...) never appear either.
    assert!(!env.contains("[137, 80"), "{env}");
    // A status from a newer peer shows its number.
    let newer = PresenceUpdate {
        account_id: 1,
        status: 99,
        custom_status: String::new(),
    };
    assert!(format!("{newer:?}").contains("Unknown(99)"));
    let set = SetPresence {
        status: None,
        afk: None,
        custom_status: Some("brb".to_owned()),
    };
    assert!(!format!("{set:?}").contains("brb"), "{set:?}");
}

#[test]
fn debug_output_redacts_peer_filled_fields_after_decoding() {
    // What a peer could send: its own error text and an arbitrary list body.
    let sent = [
        Envelope {
            request_id: 1,
            last: true,
            body: Some(Body::Error(Error {
                code: 99,
                message: "peer-secret".to_owned(),
                retry_after_ms: Some(1500),
                // Redacted inside an Error too.
                device_list: Some(SignedDeviceList {
                    body: vec![0xab; 8],
                    signature: vec![0xcd; 4],
                }),
            })),
        },
        Envelope {
            request_id: 0,
            last: false,
            body: Some(Body::Welcome(Welcome {
                device_list: Some(SignedDeviceList {
                    body: vec![0xab; 8],
                    signature: vec![0xcd; 4],
                }),
                ..Welcome::default()
            })),
        },
    ];
    for env in sent {
        let decoded = Envelope::decode(env.encode_to_vec().as_slice()).unwrap();
        let shown = format!("{decoded:?}");
        assert!(!shown.contains("peer-secret"), "{shown}");
        assert!(!shown.contains("171"), "{shown}"); // 0xab, as a number...
        assert!(!shown.contains("abab"), "{shown}"); // ...or as hex
        assert!(
            shown.contains("message: <11 bytes>") || shown.contains("body: <8 bytes>"),
            "{shown}"
        );
        // The rest stays visible: the retry hint and the (public) signature.
        assert!(
            shown.contains("retry_after_ms: Some(1500)")
                || shown.contains("signature: [205, 205, 205, 205]"),
            "{shown}"
        );
    }
    // An unknown code shows its number; a known one its name.
    let known = format!("{:?}", Error::new(ErrorCode::Invalid, "x"));
    assert!(known.contains("Invalid"), "{known}");
    let newer = Error {
        code: 99,
        message: String::new(),
        retry_after_ms: None,
        device_list: None,
    };
    assert!(format!("{newer:?}").contains("Unknown(99)"));
}

#[test]
fn an_unknown_error_code_is_an_error_not_a_normal_close() {
    let newer = Error {
        code: 1000,
        message: String::new(),
        retry_after_ms: None,
        device_list: None,
    };
    assert_eq!(WireCode::of_error(&newer), WireCode::Unknown(1000));
    assert!(!WireCode::of_error(&newer).is_normal_close());
    assert_eq!(WireCode::of_close(1000), WireCode::Unknown(1000));
    assert_eq!(WireCode::of_close(u64::MAX), WireCode::Unknown(i64::MAX));
    // Above 32 bits: never truncated into a known code (or a normal close).
    assert_eq!(WireCode::of_close(1 << 32), WireCode::Unknown(1 << 32));
    assert!(!WireCode::of_close(1 << 32).is_normal_close());
    let negative = Error {
        code: -1,
        message: String::new(),
        retry_after_ms: None,
        device_list: None,
    };
    assert_eq!(WireCode::of_error(&negative), WireCode::Unknown(-1));

    assert!(WireCode::of_close(0).is_normal_close());
    for code in [
        ErrorCode::SlowConsumer,
        ErrorCode::SessionReplaced,
        ErrorCode::MemberRemoved,
    ] {
        assert_eq!(WireCode::of_close(code.close_code()), WireCode::Known(code));
        let error = Error {
            code: code.into(),
            message: String::new(),
            retry_after_ms: None,
            device_list: None,
        };
        assert_eq!(WireCode::of_error(&error), WireCode::Known(code));
    }
}

#[test]
fn debug_output_redacts_redeem_codes_invite_codes_and_passwords() {
    let shown = [
        format!(
            "{:?}",
            Redeem {
                code: Some(redeem::Code::ClaimCode("claim-code-text".to_owned())),
            }
        ),
        format!(
            "{:?}",
            Redeem {
                code: Some(redeem::Code::InviteCode("invite-code-text".to_owned())),
            }
        ),
        format!(
            "{:?}",
            InviteCreated {
                invite: Some(invite()),
                code: "invite-code-text".to_owned(),
            }
        ),
        format!(
            "{:?}",
            SetChannelPassword {
                channel_id: 5,
                password: Some("password-text".to_owned()),
            }
        ),
    ];
    for shown in &shown {
        for secret in ["claim-code-text", "invite-code-text", "password-text"] {
            assert!(!shown.contains(secret), "{secret} in {shown}");
        }
    }
    // The shape stays: which code it was and how long, and the invite itself.
    assert_eq!(shown[0], "Redeem { code: Some(ClaimCode(<15 bytes>)) }");
    assert_eq!(shown[1], "Redeem { code: Some(InviteCode(<16 bytes>)) }");
    assert!(
        shown[2].contains("uses: 1") && shown[2].contains("code: <16 bytes>"),
        "{}",
        shown[2]
    );
    assert!(
        shown[3].contains("password: Some(<13 bytes>)"),
        "{}",
        shown[3]
    );
    // A channel kind shows its name, or a newer peer's number.
    let kind = format!("{:?}", channel());
    assert!(kind.contains("kind: Voice"), "{kind}");
    let newer = format!(
        "{:?}",
        Channel {
            kind: 99,
            ..channel()
        }
    );
    assert!(newer.contains("kind: Unknown(99)"), "{newer}");
}

#[test]
fn permission_values_are_their_bits() {
    // § 8.3: value N is bit N - 1, in the table's order, dense from 1.
    for (permission, bit) in [
        (Permission::ViewChannel, 0),
        (Permission::Administrator, 14),
        (Permission::SendMessages, 15),
        (Permission::UseCommands, 27),
        (Permission::Connect, 28),
        (Permission::CreateTempChannel, 40),
    ] {
        assert_eq!(permission.bit(), Some(1 << bit), "{permission:?}");
    }
    assert_eq!(Permission::Unspecified.bit(), None);
    for value in 1..=41 {
        let permission = Permission::try_from(value).unwrap();
        assert_eq!(permission.bit(), Some(1 << (value - 1)));
    }
    assert!(Permission::try_from(42).is_err());
}

#[test]
fn debug_output_redacts_every_patch_command() {
    let shown = [
        format!(
            "{:?}",
            UpdateSpace {
                name: Some("patch-text".to_owned()),
                description: Some("patch-text".to_owned()),
                rules: Some("patch-text".to_owned()),
                ..UpdateSpace::default()
            }
        ),
        format!(
            "{:?}",
            UpdateChannel {
                channel_id: 5,
                name: Some("patch-text".to_owned()),
                topic: Some("patch-text".to_owned()),
                ..UpdateChannel::default()
            }
        ),
        format!(
            "{:?}",
            CreateRole {
                name: "patch-text".to_owned(),
                ..CreateRole::default()
            }
        ),
        format!(
            "{:?}",
            UpdateRole {
                role_id: 2,
                name: Some("patch-text".to_owned()),
                ..UpdateRole::default()
            }
        ),
        format!(
            "{:?}",
            UpdateProfile {
                display_name: Some("patch-text".to_owned()),
                bio: Some("patch-text".to_owned()),
                pronouns: Some("patch-text".to_owned()),
            }
        ),
        format!(
            "{:?}",
            SetNickname {
                account_id: 43,
                nickname: Some("patch-text".to_owned()),
            }
        ),
        format!(
            "{:?}",
            UploadImageRequest {
                data: vec![0xab; 6],
                purpose: 0,
            }
        ),
    ];
    for shown in &shown {
        assert!(!shown.contains("patch-text"), "{shown}");
        assert!(!shown.contains("171"), "{shown}"); // 0xab
        assert!(
            shown.contains("<10 bytes>") || shown.contains("<6 bytes>"),
            "{shown}"
        );
    }
}

/// The M5 enums print by name, and a value from a newer peer as `Unknown`
/// (§ 6.11): never a bare number.
#[test]
fn debug_output_names_the_m5_enums() {
    let (_, env) = m5_examples()
        .into_iter()
        .find(|(n, _)| *n == "m5_update_space")
        .unwrap();
    let shown = format!("{env:?}");
    assert!(shown.contains("VoiceFirst"), "{shown}");
    assert!(shown.contains("MembersInChannel"), "{shown}");
    let newer = Space {
        style: 99,
        voice_chat_access: 98,
        ..Space::default()
    };
    let shown = format!("{newer:?}");
    assert!(shown.contains("style: Unknown(99)"), "{shown}");
    assert!(shown.contains("voice_chat_access: Unknown(98)"), "{shown}");
    let shown = format!(
        "{:?}",
        SpacePublicInfo {
            style: SpaceStyle::TextFirst.into(),
            ..SpacePublicInfo::default()
        }
    );
    assert!(shown.contains("style: TextFirst"), "{shown}");
}

#[test]
fn every_m3_example_carries_its_secrets_only_in_redacted_form() {
    // Each secret is on the wire (so the Debug test above is not vacuous)...
    let wire: Vec<Vec<u8>> = m3_examples()
        .iter()
        .map(|(_, env)| env.encode_to_vec())
        .collect();
    for text in M3_SECRETS.iter().filter(|t| !t.starts_with("205")) {
        assert!(
            wire.iter()
                .any(|bytes| bytes.windows(text.len()).any(|w| w == text.as_bytes())),
            "{text} is in no M3 example"
        );
    }
    // ...and shown only as its length.
    for (name, env) in m3_examples() {
        let shown = format!("{env:?}");
        for text in M3_SECRETS {
            assert!(!shown.contains(text), "{name}: {text} in {shown}");
        }
    }
}

#[test]
fn the_join_voice_password_is_on_the_wire_and_only_redacted_in_debug() {
    let (_, env) = m4_examples()
        .into_iter()
        .find(|(n, _)| *n == "m4_join_voice")
        .unwrap();
    let secret = "voice-password-text";
    let bytes = env.encode_to_vec();
    assert!(bytes.windows(secret.len()).any(|w| w == secret.as_bytes()));
    for (name, env) in m4_examples() {
        let shown = format!("{env:?}");
        assert!(!shown.contains(secret), "{name}: {shown}");
        assert!(!shown.contains("channel-text"), "{name}: {shown}");
    }
}

#[test]
fn each_body_and_kind_names_the_minor_that_added_it() {
    use yapsta_proto::minor_of;
    let minor = |name: &str| {
        let (_, env) = examples().into_iter().find(|(n, _)| *n == name).unwrap();
        minor_of(&env.body.unwrap())
    };
    for (name, expected) in [
        ("error", 1),
        ("event_member_joined", 1),
        ("m3_event_message_created", 1),
        ("command_create_channel", 2),
        ("m3_command_update_channel", 2),
        ("m3_upload_emoji_image", 2),
        ("m3_start_typing", 3),
    ] {
        assert_eq!(minor(name), expected, "{name}");
    }
    // Every M3 command and request kind is minor 3: a minor-2 session that
    // sends one is refused for its version (§ 6.7). The two M2 kinds above
    // only gained M3 fields.
    let mut m3_kinds = 0;
    for (name, env) in m3_examples() {
        let body = env.body.unwrap();
        if matches!(body, Body::Command(_) | Body::Request(_))
            && !["m3_command_update_channel", "m3_upload_emoji_image"].contains(&name)
        {
            assert_eq!(minor_of(&body), 3, "{name}");
            m3_kinds += 1;
        }
    }
    assert_eq!(
        m3_kinds,
        14 + 9,
        "every M3 command and request kind has an example"
    );
    // Every M4 command kind is minor 4 (§ 6.7); `create_channel` only gained
    // the `temporary` field, events, ephemerals and snapshots are server-sent.
    let mut m4_kinds = 0;
    for (name, env) in m4_examples() {
        let body = env.body.unwrap();
        let expected = match (&body, name) {
            (_, "m4_create_temporary_channel") => 2,
            (Body::Command(_), _) => 4,
            (Body::Resync(_), _) => 2,
            _ => 1,
        };
        assert_eq!(minor_of(&body), expected, "{name}");
        m4_kinds += usize::from(expected == 4);
    }
    assert_eq!(m4_kinds, 8, "every M4 command kind has an example");
    // M5 adds one command kind (minor 5); `update_space` only gained fields,
    // which the session gates on their own (§ 6.11 "Minor 5").
    for (name, expected) in [
        ("m5_apply_template", 5),
        ("m5_update_space", 2),
        ("m5_event_space_updated", 1),
        ("m5_hello", 1),
    ] {
        assert_eq!(minor(name), expected, "{name}");
    }
    // Every M6 command and request kind is minor 6 (§ 6.12 "Minor 6");
    // responses, events and the hello are server-sent.
    let mut m6_kinds = 0;
    for (name, env) in m6_examples() {
        let body = env.body.unwrap();
        let expected = match &body {
            Body::Command(_) | Body::Request(_) => 6,
            Body::Response(_) => 2,
            _ => 1,
        };
        assert_eq!(minor_of(&body), expected, "{name}");
        m6_kinds += usize::from(expected == 6);
    }
    assert_eq!(
        m6_kinds,
        5 + 2,
        "every M6 command and request kind has an example"
    );
    // M7 adds a redeem variant (minor 7); `update_space` only gained fields,
    // which the session gates on their own (§ 6.14, § 6.7 "Minor 7").
    for (name, expected) in [
        ("m7_redeem_open_join", 7),
        ("m7_update_space", 2),
        ("m7_update_space_no_roles", 2),
        ("m7_event_space_updated", 1),
        ("m7_hello", 1),
    ] {
        assert_eq!(minor(name), expected, "{name}");
    }
    // The older redeem variants stay minor 2.
    for code in [
        redeem::Code::ClaimCode("c".to_owned()),
        redeem::Code::InviteCode("i".to_owned()),
    ] {
        assert_eq!(minor_of(&Body::Redeem(Redeem { code: Some(code) })), 2);
    }
    assert_eq!(minor_of(&Body::Redeem(Redeem { code: None })), 2);
    // An unset kind is refused as unknown, not for its version.
    assert_eq!(minor_of(&Body::Command(Command { kind: None })), 2);
    assert_eq!(minor_of(&Body::Request(Request { kind: None })), 2);
}
