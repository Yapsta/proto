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
        bot: false,
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
        ciphertext: vec![],
        dm_kind: 0,
        mls_epoch: 0,
        dm_id: None,
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
        webhook_id: None,
        webhook_name: None,
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
                    dm_id: None,
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
                    dm_id: None,
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
                    mls_external_sender: None,
                    push_info: None,
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
        receiving_audio: false,
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
                    receiving_audio: None,
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

/// The SDP and TURN values in [`m7_media_examples`]: none may appear in
/// `Debug` output.
const M7_SECRETS: &[&str] = &[
    "v=0 o=- publish-offer",
    "v=0 o=- publish-answer",
    "v=0 o=- subscribe-offer",
    "v=0 o=- subscribe-answer",
    "turn:turn.example.org:3478",
    "turn-user-text",
    "turn-password-text",
];

/// The secret and user text in [`m8_examples`]: none may appear in `Debug`.
const M8_SECRETS: &[&str] = &[
    "aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq",
    "bot-name-text",
];

fn bot() -> Bot {
    Bot {
        account_id: 120,
        name: "bot-name-text".to_owned(),
        created_at: 1_800_000_000,
        created_by: 42,
    }
}

/// One example of every M8 wire-A kind and field (§ 6.15).
fn m8_examples() -> Vec<(&'static str, Envelope)> {
    use command::Kind as C;
    let env = |request_id, last, body| Envelope {
        request_id,
        last,
        body: Some(body),
    };
    let command = |request_id, kind| {
        env(
            request_id,
            false,
            Body::Command(Command { kind: Some(kind) }),
        )
    };
    vec![
        (
            "m8_auth_bot",
            env(
                0,
                false,
                Body::Auth(Auth {
                    version: 8,
                    credential: Some(auth::Credential::Bot(BotCredential {
                        bot_pub: vec![0xb0; 32],
                        signature: vec![0x5a; 64],
                    })),
                    ..Auth::default()
                }),
            ),
        ),
        (
            "m8_event_bot_joined",
            env(
                0,
                false,
                Body::Event(Event {
                    seq: 30,
                    kind: Some(event::Kind::MemberJoined(MemberJoined {
                        member: Some(Member {
                            account_id: 120,
                            joined_at: 1_800_000_000,
                            bot: true,
                            ..Member::default()
                        }),
                    })),
                }),
            ),
        ),
        (
            "m8_event_voice_state_receiving",
            env(
                0,
                false,
                Body::Event(Event {
                    seq: 31,
                    kind: Some(event::Kind::VoiceStateUpdated(VoiceStateUpdated {
                        state: Some(VoiceState {
                            receiving_audio: true,
                            ..voice_state()
                        }),
                        previous_channel_id: 0,
                    })),
                }),
            ),
        ),
        (
            "m8_set_voice_state_receiving",
            command(
                130,
                C::SetVoiceState(SetVoiceState {
                    receiving_audio: Some(true),
                    ..SetVoiceState::default()
                }),
            ),
        ),
        (
            "m8_create_bot",
            command(
                131,
                C::CreateBot(CreateBot {
                    name: "bot-name-text".to_owned(),
                }),
            ),
        ),
        (
            "m8_rotate_bot",
            command(132, C::RotateBot(RotateBot { account_id: 120 })),
        ),
        (
            "m8_delete_bot",
            command(133, C::DeleteBot(DeleteBot { account_id: 120 })),
        ),
        (
            "m8_bot_created",
            env(
                131,
                true,
                Body::CommandResult(CommandResult {
                    kind: Some(command_result::Kind::BotCreated(BotCreated {
                        bot: Some(bot()),
                        seed: M8_SECRETS[0].to_owned(),
                    })),
                }),
            ),
        ),
        (
            "m8_bot_list_request",
            env(
                134,
                false,
                Body::Request(Request {
                    kind: Some(request::Kind::BotList(BotListRequest {})),
                }),
            ),
        ),
        (
            "m8_bot_list",
            env(
                134,
                true,
                Body::Response(Response {
                    kind: Some(response::Kind::BotList(BotList { bots: vec![bot()] })),
                }),
            ),
        ),
    ]
}

/// The secret and user text in [`m8_wire_b_examples`]: none may appear in
/// `Debug`. The last two are option values that are not text (an integer and a
/// member's id), which `Debug` leaves out as well.
const M8B_SECRETS: &[&str] = &[
    "webhook-token-text",
    "webhook-name-text",
    "command-description-text",
    "option-description-text",
    "option-value-text",
    "987654321",
    "31337",
];

fn slash_command() -> SlashCommand {
    SlashCommand {
        name: "roll".to_owned(),
        description: M8B_SECRETS[2].to_owned(),
        options: vec![CommandOption {
            name: "sides".to_owned(),
            description: M8B_SECRETS[3].to_owned(),
            kind: CommandOptionKind::Integer as i32,
            required: true,
        }],
    }
}

/// One value of each kind: the values are never shown.
fn option_values() -> Vec<CommandOptionValue> {
    use command_option_value::Value;
    [
        ("say", Value::Text(M8B_SECRETS[4].to_owned())),
        ("sides", Value::Integer(-987_654_321)),
        ("loud", Value::Boolean(true)),
        ("who", Value::AccountId(31_337)),
        ("where", Value::ChannelId(5)),
    ]
    .into_iter()
    .map(|(name, value)| CommandOptionValue {
        name: name.to_owned(),
        value: Some(value),
    })
    .collect()
}

fn webhook() -> Webhook {
    Webhook {
        id: 150,
        channel_id: 5,
        name: M8B_SECRETS[1].to_owned(),
        created_by: 42,
        created_at: 1_800_000_000,
    }
}

/// One example of every M8 wire-B kind and field (§ 6.15): slash commands
/// and webhooks.
fn m8_wire_b_examples() -> Vec<(&'static str, Envelope)> {
    use command::Kind as C;
    let env = |request_id, last, body| Envelope {
        request_id,
        last,
        body: Some(body),
    };
    let command = |request_id, kind| {
        env(
            request_id,
            false,
            Body::Command(Command { kind: Some(kind) }),
        )
    };
    let request = |request_id, kind| {
        env(
            request_id,
            false,
            Body::Request(Request { kind: Some(kind) }),
        )
    };
    let response = |request_id, kind| {
        env(
            request_id,
            true,
            Body::Response(Response { kind: Some(kind) }),
        )
    };
    vec![
        (
            "m8_register_commands",
            command(
                140,
                C::RegisterCommands(RegisterCommands {
                    commands: vec![slash_command()],
                }),
            ),
        ),
        (
            "m8_invoke_command",
            command(
                141,
                C::InvokeCommand(InvokeCommand {
                    bot_account_id: 120,
                    channel_id: 5,
                    name: "roll".to_owned(),
                    options: option_values(),
                }),
            ),
        ),
        (
            "m8_create_webhook",
            command(
                142,
                C::CreateWebhook(CreateWebhook {
                    channel_id: 5,
                    name: M8B_SECRETS[1].to_owned(),
                }),
            ),
        ),
        (
            "m8_delete_webhook",
            command(143, C::DeleteWebhook(DeleteWebhook { webhook_id: 150 })),
        ),
        (
            "m8_command_list_request",
            request(
                144,
                request::Kind::CommandList(CommandListRequest {
                    bot_account_id: 120,
                }),
            ),
        ),
        (
            "m8_webhook_list_request",
            request(145, request::Kind::WebhookList(WebhookListRequest {})),
        ),
        (
            "m8_webhook_created",
            env(
                142,
                true,
                Body::CommandResult(CommandResult {
                    kind: Some(command_result::Kind::WebhookCreated(WebhookCreated {
                        webhook: Some(webhook()),
                        token: M8B_SECRETS[0].to_owned(),
                    })),
                }),
            ),
        ),
        (
            "m8_command_list",
            response(
                144,
                response::Kind::CommandList(CommandList {
                    bot_account_id: 120,
                    commands: vec![slash_command()],
                }),
            ),
        ),
        (
            "m8_webhook_list",
            response(
                145,
                response::Kind::WebhookList(WebhookList {
                    webhooks: vec![webhook()],
                }),
            ),
        ),
        (
            "m8_event_commands_updated",
            env(
                0,
                false,
                Body::Event(Event {
                    seq: 32,
                    kind: Some(event::Kind::CommandsUpdated(CommandsUpdated {
                        bot_account_id: 120,
                    })),
                }),
            ),
        ),
        (
            "m8_interaction",
            env(
                0,
                false,
                Body::Ephemeral(Ephemeral {
                    kind: Some(ephemeral::Kind::Interaction(Interaction {
                        invoker_id: 42,
                        channel_id: 5,
                        name: "roll".to_owned(),
                        options: option_values(),
                    })),
                }),
            ),
        ),
        (
            "m8_event_webhook_message",
            env(
                0,
                false,
                Body::Event(Event {
                    seq: 33,
                    kind: Some(event::Kind::MessageCreated(MessageCreated {
                        message: Some(yapsta_proto::v1::Message {
                            id: 71,
                            channel_id: 5,
                            author_id: 0,
                            created_at: 1_800_000_300,
                            content: "webhook-post-text".to_owned(),
                            webhook_id: Some(150),
                            webhook_name: Some(M8B_SECRETS[1].to_owned()),
                            ..yapsta_proto::v1::Message::default()
                        }),
                    })),
                }),
            ),
        ),
    ]
}

/// M10 (§ 6.17, § 6.18): user text and device secrets the examples plant,
/// none of which may show in `Debug`.
const M10_SECRETS: &[&str] = &[
    "m10-dm-secret-text",
    "m10-dm-edit-text",
    "m10-group-name",
    "m10-renamed-group",
    "m10-endpoint-secret",
    "[109, 49, 48",
    "[102, 102, 102",
];

fn m10_command(request_id: u32, kind: command::Kind) -> Envelope {
    Envelope {
        request_id,
        last: false,
        body: Some(Body::Command(Command { kind: Some(kind) })),
    }
}

fn m10_personal(seq: u64, kind: personal_event::Kind) -> Envelope {
    Envelope {
        request_id: 0,
        last: false,
        body: Some(Body::Personal(PersonalEvent {
            seq,
            kind: Some(kind),
        })),
    }
}

/// M10 (§ 6.3, § 6.17, § 6.18): every new command and request, the personal
/// bodies, `Welcome.push_info` and the DM typing fields.
fn m10_examples() -> Vec<(&'static str, Envelope)> {
    use command::Kind as C;
    let dm_message = yapsta_proto::v1::Message {
        ciphertext: vec![],
        dm_kind: 0,
        mls_epoch: 0,
        id: 181,
        channel_id: 0,
        thread_id: None,
        author_id: 171,
        created_at: 1_700_000_100,
        content: "m10-dm-secret-text".to_owned(),
        reply_to: None,
        mentions: None,
        attachments: vec![],
        reactions: vec![],
        edited_at: None,
        deleted: false,
        pinned: false,
        webhook_id: None,
        webhook_name: None,
        dm_id: Some(180),
    };
    let group = Dm {
        encryption: 0,
        successor_dm_id: None,
        mls_group_id: vec![],
        id: 180,
        kind: DmKind::Group.into(),
        member_ids: vec![170, 171, 172],
        name: "m10-group-name".to_owned(),
        owner_id: 170,
        created_at: 1_700_000_000,
    };
    let read_state = DmReadState {
        dm_id: 180,
        last_read_id: 181,
        mention_count: 2,
        last_message_id: 182,
    };
    let setting = NotificationSetting {
        target: NotifyTarget::Dm.into(),
        target_id: 180,
        level: NotifyLevel::Mentions.into(),
        muted_until: 1_800_000_000,
    };
    let emoji = Some(EmojiRef {
        emoji: Some(emoji_ref::Emoji::CustomId(183)),
    });
    vec![
        (
            "m10_open_dm",
            m10_command(
                170,
                C::OpenDm(OpenDm {
                    reserved_dm_id: None,
                    commit: None,
                    account_id: 171,
                }),
            ),
        ),
        (
            "m10_create_group_dm",
            m10_command(
                171,
                C::CreateGroupDm(CreateGroupDm {
                    reserved_dm_id: None,
                    commit: None,
                    account_ids: vec![171, 172],
                    name: Some("m10-group-name".to_owned()),
                }),
            ),
        ),
        (
            "m10_add_dm_member",
            m10_command(
                172,
                C::AddDmMember(AddDmMember {
                    commit: None,
                    dm_id: 180,
                    account_id: 173,
                }),
            ),
        ),
        (
            "m10_remove_dm_member",
            m10_command(
                173,
                C::RemoveDmMember(RemoveDmMember {
                    dm_id: 180,
                    account_id: 173,
                }),
            ),
        ),
        (
            "m10_leave_dm",
            m10_command(174, C::LeaveDm(LeaveDm { dm_id: 180 })),
        ),
        (
            "m10_update_dm",
            m10_command(
                175,
                C::UpdateDm(UpdateDm {
                    dm_id: 180,
                    name: "m10-renamed-group".to_owned(),
                }),
            ),
        ),
        (
            "m10_send_dm_message",
            m10_command(
                176,
                C::SendDmMessage(SendDmMessage {
                    ciphertext: vec![],
                    kind: 0,
                    delete_id: None,
                    dm_id: 180,
                    content: "m10-dm-secret-text".to_owned(),
                    reply_to: Some(181),
                    attachment_ids: vec![184],
                }),
            ),
        ),
        (
            "m10_edit_dm_message",
            m10_command(
                177,
                C::EditDmMessage(EditDmMessage {
                    dm_id: 180,
                    message_id: 181,
                    content: "m10-dm-edit-text".to_owned(),
                }),
            ),
        ),
        (
            "m10_delete_dm_message",
            m10_command(
                178,
                C::DeleteDmMessage(DeleteDmMessage {
                    dm_id: 180,
                    message_id: 181,
                }),
            ),
        ),
        (
            "m10_add_dm_reaction",
            m10_command(
                179,
                C::AddDmReaction(AddDmReaction {
                    dm_id: 180,
                    message_id: 181,
                    emoji: emoji.clone(),
                }),
            ),
        ),
        (
            "m10_remove_dm_reaction",
            m10_command(
                180,
                C::RemoveDmReaction(RemoveDmReaction {
                    dm_id: 180,
                    message_id: 181,
                    emoji: emoji.clone(),
                }),
            ),
        ),
        (
            "m10_mark_dm_read",
            m10_command(
                181,
                C::MarkDmRead(MarkDmRead {
                    dm_id: 180,
                    message_id: 181,
                }),
            ),
        ),
        (
            "m10_block",
            m10_command(182, C::Block(Block { account_id: 171 })),
        ),
        (
            "m10_unblock",
            m10_command(183, C::Unblock(Unblock { account_id: 171 })),
        ),
        (
            "m10_set_notification_setting",
            m10_command(
                184,
                C::SetNotificationSetting(SetNotificationSetting {
                    setting: Some(setting),
                }),
            ),
        ),
        (
            "m10_register_push_web",
            m10_command(
                185,
                C::RegisterPush(RegisterPush {
                    target: Some(register_push::Target::WebPush(WebPushTarget {
                        endpoint: "https://push.example/m10-endpoint-secret".to_owned(),
                        p256dh: vec![4; 65],
                        auth: vec![0x66; 16],
                    })),
                }),
            ),
        ),
        (
            "m10_register_push_relay",
            m10_command(
                186,
                C::RegisterPush(RegisterPush {
                    target: Some(register_push::Target::Relay(RelayTarget {
                        token: b"m10-relay-token".to_vec(),
                    })),
                }),
            ),
        ),
        (
            "m10_unregister_push",
            m10_command(187, C::UnregisterPush(UnregisterPush {})),
        ),
        (
            "m10_go_background",
            m10_command(188, C::GoBackground(GoBackground {})),
        ),
        (
            "m10_dm_history",
            Envelope {
                request_id: 189,
                last: false,
                body: Some(Body::Request(Request {
                    kind: Some(request::Kind::DmHistory(DmHistoryRequest {
                        dm_id: 180,
                        anchor: Some(dm_history_request::Anchor::Before(181)),
                        limit: 50,
                    })),
                })),
            },
        ),
        (
            "m10_list_dms",
            Envelope {
                request_id: 190,
                last: false,
                body: Some(Body::Request(Request {
                    kind: Some(request::Kind::ListDms(ListDmsRequest {
                        before_message_id: Some(182),
                        before_dm_id: Some(180),
                        limit: 100,
                    })),
                })),
            },
        ),
        (
            "m10_response_dms",
            Envelope {
                request_id: 190,
                last: true,
                body: Some(Body::Response(Response {
                    kind: Some(response::Kind::Dms(DmList {
                        dms: vec![group.clone()],
                        has_more: true,
                        read_states: vec![read_state],
                    })),
                })),
            },
        ),
        (
            "m10_personal_dm_updated",
            m10_personal(
                1,
                personal_event::Kind::DmUpdated(DmUpdated {
                    dm: Some(group.clone()),
                }),
            ),
        ),
        (
            "m10_personal_dm_message_created",
            m10_personal(
                2,
                personal_event::Kind::DmMessageCreated(MessageCreated {
                    message: Some(dm_message.clone()),
                }),
            ),
        ),
        (
            "m10_personal_block_updated",
            m10_personal(
                3,
                personal_event::Kind::BlockUpdated(BlockUpdated {
                    account_id: 171,
                    blocked: true,
                }),
            ),
        ),
        (
            "m10_personal_notification_setting_updated",
            m10_personal(
                4,
                personal_event::Kind::NotificationSettingUpdated(NotificationSettingUpdated {
                    setting: Some(setting),
                }),
            ),
        ),
        (
            "m10_personal_snapshot",
            Envelope {
                request_id: 0,
                last: false,
                body: Some(Body::PersonalSnapshot(PersonalSnapshot {
                    seq: 4,
                    dms: vec![group],
                    dm_read_states: vec![read_state],
                    blocked_account_ids: vec![171],
                    notification_settings: vec![setting],
                })),
            },
        ),
        (
            "m10_welcome_push_info",
            Envelope {
                request_id: 0,
                last: false,
                body: Some(Body::Welcome(Welcome {
                    mls_external_sender: None,
                    session_id: 191,
                    account_id: Some(170),
                    membership: None,
                    resume_token: None,
                    device_list: None,
                    state: None,
                    push_info: Some(PushInfo {
                        vapid_public_key: vec![7; 65],
                        relay: true,
                        registered: false,
                    }),
                })),
            },
        ),
        (
            "m10_start_typing_dm",
            Envelope {
                request_id: 0,
                last: false,
                body: Some(Body::StartTyping(StartTyping {
                    channel_id: 0,
                    thread_id: None,
                    dm_id: Some(180),
                })),
            },
        ),
        (
            "m10_ephemeral_typing_dm",
            Envelope {
                request_id: 0,
                last: false,
                body: Some(Body::Ephemeral(Ephemeral {
                    kind: Some(ephemeral::Kind::Typing(Typing {
                        channel_id: 0,
                        thread_id: None,
                        account_id: 171,
                        dm_id: Some(180),
                    })),
                })),
            },
        ),
        (
            "m10_dm_history_after",
            Envelope {
                request_id: 192,
                last: false,
                body: Some(Body::Request(Request {
                    kind: Some(request::Kind::DmHistory(DmHistoryRequest {
                        dm_id: 180,
                        anchor: Some(dm_history_request::Anchor::After(181)),
                        limit: 20,
                    })),
                })),
            },
        ),
        (
            "m10_dm_history_around",
            Envelope {
                request_id: 193,
                last: false,
                body: Some(Body::Request(Request {
                    kind: Some(request::Kind::DmHistory(DmHistoryRequest {
                        dm_id: 180,
                        anchor: Some(dm_history_request::Anchor::Around(181)),
                        limit: 30,
                    })),
                })),
            },
        ),
        (
            "m10_personal_dm_removed",
            m10_personal(5, personal_event::Kind::DmRemoved(DmRemoved { dm_id: 180 })),
        ),
        (
            "m10_personal_dm_message_updated",
            m10_personal(
                6,
                personal_event::Kind::DmMessageUpdated(MessageUpdated {
                    message: Some(yapsta_proto::v1::Message {
                        content: "m10-dm-edit-text".to_owned(),
                        edited_at: Some(1_700_000_200),
                        ..dm_message.clone()
                    }),
                }),
            ),
        ),
        (
            "m10_personal_dm_message_deleted",
            m10_personal(
                7,
                personal_event::Kind::DmMessageDeleted(DmMessageDeleted {
                    dm_id: 180,
                    message_id: 181,
                }),
            ),
        ),
        (
            "m10_personal_dm_reaction_added",
            m10_personal(
                8,
                personal_event::Kind::DmReactionAdded(DmReactionAdded {
                    dm_id: 180,
                    message_id: 181,
                    emoji: emoji.clone(),
                    account_id: 172,
                }),
            ),
        ),
        (
            "m10_personal_dm_reaction_removed",
            m10_personal(
                9,
                personal_event::Kind::DmReactionRemoved(DmReactionRemoved {
                    dm_id: 180,
                    message_id: 181,
                    emoji,
                    account_id: 172,
                }),
            ),
        ),
        (
            "m10_personal_dm_read_state",
            m10_personal(10, personal_event::Kind::DmReadState(read_state)),
        ),
        (
            "m10_hello_push",
            Envelope {
                request_id: 0,
                last: false,
                body: Some(Body::Hello(Hello {
                    server_id: "a5jy5opmsxgrcsn22buvxzm5qi".to_owned(),
                    versions: vec![10, 9],
                    challenge: vec![1; 32],
                    capabilities: vec![Capability::Push.into()],
                    space_public_info: None,
                })),
            },
        ),
        (
            "m10_auth_resume_personal",
            Envelope {
                request_id: 0,
                last: false,
                body: Some(Body::Auth(Auth {
                    version: 10,
                    credential: None,
                    capabilities: vec![],
                    client_info: None,
                    presence: None,
                    resume: Some(Resume {
                        token: vec![4; 32],
                        last_seq: 99,
                        personal_last_seq: Some(10),
                    }),
                })),
            },
        ),
    ]
}

/// M9 (§ 6.16): `delete_thread` and `thread_deleted`, the minor's whole new surface besides
/// the `AuditAction` values ([`m9_audit_actions_are_pinned`]).
fn m9_examples() -> Vec<(&'static str, Envelope)> {
    vec![
        (
            "m9_delete_thread",
            Envelope {
                request_id: 160,
                last: false,
                body: Some(Body::Command(Command {
                    kind: Some(command::Kind::DeleteThread(DeleteThread { thread_id: 161 })),
                })),
            },
        ),
        (
            "m9_event_thread_deleted",
            Envelope {
                request_id: 0,
                last: false,
                body: Some(Body::Event(Event {
                    seq: 33,
                    kind: Some(event::Kind::ThreadDeleted(ThreadDeleted {
                        channel_id: 5,
                        thread_id: 161,
                    })),
                })),
            },
        ),
    ]
}

/// Minor 11 (§ 6.17, "DM modes"): `Space.dm_mode`, in the snapshot form and
/// in `space_updated`.
fn m11_examples() -> Vec<(&'static str, Envelope)> {
    vec![
        (
            "m11_event_space_updated_dm_mode",
            Envelope {
                request_id: 0,
                last: false,
                body: Some(Body::Event(Event {
                    seq: 1100,
                    kind: Some(event::Kind::SpaceUpdated(SpaceUpdated {
                        space: Some(Space {
                            dm_mode: DmMode::Off.into(),
                            ..space()
                        }),
                    })),
                })),
            },
        ),
        (
            "m11_hello",
            Envelope {
                request_id: 0,
                last: false,
                body: Some(Body::Hello(Hello {
                    server_id: "a5jy5opmsxgrcsn22buvxzm5qi".to_owned(),
                    versions: vec![11, 10],
                    challenge: vec![1; 32],
                    capabilities: vec![],
                    space_public_info: None,
                })),
            },
        ),
    ]
}

/// Minor 11 (§ 6.19) MLS bytes planted in the examples, each a run of one
/// byte value so the Debug test can look for it: none may show.
const MLS_SECRET_BYTE: u8 = 0xe7;

fn mls_bytes(len: usize) -> Vec<u8> {
    vec![MLS_SECRET_BYTE; len]
}

fn mls_commit() -> MlsCommit {
    MlsCommit {
        epoch: 4,
        commit: mls_bytes(40),
        proposals: vec![mls_bytes(20)],
        welcome: Some(mls_bytes(30)),
        group_context: mls_bytes(50),
    }
}

fn mls_message() -> yapsta_proto::v1::Message {
    yapsta_proto::v1::Message {
        id: 9,
        author_id: 3,
        created_at: 1_800_000_000,
        dm_id: Some(5),
        ciphertext: mls_bytes(256),
        dm_kind: DmMessageKind::Message.into(),
        mls_epoch: 4,
        ..Default::default()
    }
}

/// Minor 11 (§ 6.19): every MLS command, request, response and body, and
/// the fields minor 11 adds to older messages.
fn m11_mls_examples() -> Vec<(&'static str, Envelope)> {
    let cmd = |request_id, kind| Envelope {
        request_id,
        last: false,
        body: Some(Body::Command(Command { kind: Some(kind) })),
    };
    let req = |request_id, kind| Envelope {
        request_id,
        last: false,
        body: Some(Body::Request(Request { kind: Some(kind) })),
    };
    let resp = |request_id, kind| Envelope {
        request_id,
        last: true,
        body: Some(Body::Response(Response { kind: Some(kind) })),
    };
    let entry = |position, entry| MlsEntry {
        dm_id: 5,
        position,
        epoch: 4,
        entry: Some(entry),
    };
    vec![
        (
            "m11_reserve_dm",
            cmd(
                200,
                command::Kind::ReserveDm(ReserveDm {
                    kind: DmKind::Group.into(),
                    account_ids: vec![7, 8],
                }),
            ),
        ),
        (
            "m11_publish_key_packages",
            cmd(
                201,
                command::Kind::PublishKeyPackages(PublishKeyPackages {
                    key_packages: vec![mls_bytes(64), mls_bytes(64)],
                    last_resort: Some(mls_bytes(64)),
                }),
            ),
        ),
        (
            "m11_submit_mls_commit",
            cmd(
                202,
                command::Kind::SubmitMlsCommit(SubmitMlsCommit {
                    dm_id: 5,
                    commit: Some(mls_commit()),
                }),
            ),
        ),
        (
            "m11_open_dm_with_commit",
            cmd(
                203,
                command::Kind::OpenDm(OpenDm {
                    account_id: 7,
                    reserved_dm_id: Some(5),
                    commit: Some(MlsCommit {
                        epoch: 0,
                        ..mls_commit()
                    }),
                }),
            ),
        ),
        (
            "m11_create_group_dm_with_commit",
            cmd(
                204,
                command::Kind::CreateGroupDm(CreateGroupDm {
                    account_ids: vec![7, 8],
                    name: None,
                    reserved_dm_id: Some(6),
                    commit: Some(mls_commit()),
                }),
            ),
        ),
        (
            "m11_add_dm_member_with_commit",
            cmd(
                205,
                command::Kind::AddDmMember(AddDmMember {
                    dm_id: 6,
                    account_id: 9,
                    commit: Some(mls_commit()),
                }),
            ),
        ),
        (
            "m11_send_dm_ciphertext",
            cmd(
                206,
                command::Kind::SendDmMessage(SendDmMessage {
                    dm_id: 5,
                    content: String::new(),
                    reply_to: None,
                    attachment_ids: vec![],
                    ciphertext: mls_bytes(256),
                    kind: DmMessageKind::Delete.into(),
                    delete_id: Some(9),
                }),
            ),
        ),
        (
            "m11_ack_mls",
            cmd(
                210,
                command::Kind::AckMls(AckMls {
                    dm_id: 5,
                    position: 16,
                }),
            ),
        ),
        (
            "m11_device_lists_request",
            req(
                207,
                request::Kind::DeviceLists(DeviceListsRequest {
                    account_ids: vec![7, 8],
                }),
            ),
        ),
        (
            "m11_claim_key_packages_request",
            req(
                208,
                request::Kind::ClaimKeyPackages(ClaimKeyPackagesRequest { account_id: 7 }),
            ),
        ),
        (
            "m11_mls_log_request",
            req(
                209,
                request::Kind::MlsLog(MlsLogRequest {
                    dm_id: 5,
                    after_position: 12,
                    limit: 100,
                }),
            ),
        ),
        (
            "m11_device_lists",
            resp(
                207,
                response::Kind::DeviceLists(DeviceLists {
                    lists: vec![AccountDeviceList {
                        account_id: 7,
                        account_pub: vec![7; 32],
                        device_list: Some(device_list()),
                    }],
                }),
            ),
        ),
        (
            "m11_key_packages",
            resp(
                208,
                response::Kind::KeyPackages(ClaimedKeyPackages {
                    key_packages: vec![ClaimedKeyPackage {
                        device_pub: vec![8; 32],
                        key_package: mls_bytes(64),
                        last_resort: true,
                    }],
                }),
            ),
        ),
        (
            "m11_mls_log",
            resp(
                209,
                response::Kind::MlsLog(MlsLog {
                    entries: vec![
                        entry(13, mls_entry::Entry::Handshake(mls_bytes(40))),
                        entry(14, mls_entry::Entry::Message(mls_message())),
                    ],
                    has_more: true,
                }),
            ),
        ),
        (
            "m11_mls_delivery",
            Envelope {
                request_id: 0,
                last: false,
                body: Some(Body::Mls(MlsDelivery {
                    entries: vec![
                        entry(15, mls_entry::Entry::Welcome(mls_bytes(30))),
                        entry(16, mls_entry::Entry::UpdateRequested(MlsUpdateRequested {})),
                        entry(0, mls_entry::Entry::Message(mls_message())),
                    ],
                })),
            },
        ),
        (
            "m11_mls_conflict",
            Envelope {
                request_id: 202,
                last: true,
                body: Some(Body::Error(Error {
                    mls_epoch: Some(5),
                    ..Error::new(ErrorCode::Conflict, "not the current epoch")
                })),
            },
        ),
        (
            "m11_welcome_external_sender",
            Envelope {
                request_id: 0,
                last: false,
                body: Some(Body::Welcome(Welcome {
                    mls_external_sender: Some(MlsExternalSender {
                        key: vec![0x41; 32],
                        certificate: vec![0x42; 64],
                    }),
                    ..Welcome::default()
                })),
            },
        ),
        (
            "m11_personal_mls_dm",
            Envelope {
                request_id: 0,
                last: false,
                body: Some(Body::Personal(PersonalEvent {
                    seq: 12,
                    kind: Some(personal_event::Kind::DmUpdated(DmUpdated {
                        dm: Some(Dm {
                            id: 5,
                            kind: DmKind::OneToOne.into(),
                            member_ids: vec![3, 7],
                            created_at: 1_800_000_000,
                            encryption: DmEncryption::Mls.into(),
                            mls_group_id: mls_bytes(16),
                            ..Dm::default()
                        }),
                    })),
                })),
            },
        ),
        (
            "m11_personal_plaintext_successor",
            Envelope {
                request_id: 0,
                last: false,
                body: Some(Body::Personal(PersonalEvent {
                    seq: 13,
                    kind: Some(personal_event::Kind::DmUpdated(DmUpdated {
                        dm: Some(Dm {
                            id: 4,
                            kind: DmKind::OneToOne.into(),
                            member_ids: vec![3, 7],
                            successor_dm_id: Some(5),
                            ..Dm::default()
                        }),
                    })),
                })),
            },
        ),
    ]
}

fn media_track() -> MediaTrack {
    MediaTrack {
        media_id: 7,
        account_id: 42,
        channel_id: 9,
        kind: MediaKind::Screen.into(),
    }
}

/// M7 (§ 6.6): the media signalling commands, replies, request, response,
/// events, ephemeral and snapshot field.
fn m7_media_examples() -> Vec<(&'static str, Envelope)> {
    use command::Kind as C;
    let env = |request_id, last, body| Envelope {
        request_id,
        last,
        body: Some(body),
    };
    let command = |request_id, kind| {
        env(
            request_id,
            false,
            Body::Command(Command { kind: Some(kind) }),
        )
    };
    vec![
        (
            "m7_publish_media",
            command(
                110,
                C::PublishMedia(PublishMedia {
                    kind: MediaKind::Screen.into(),
                    sdp_offer: M7_SECRETS[0].to_owned(),
                }),
            ),
        ),
        (
            "m7_publish_media_camera",
            command(
                111,
                C::PublishMedia(PublishMedia {
                    kind: MediaKind::Camera.into(),
                    sdp_offer: M7_SECRETS[0].to_owned(),
                }),
            ),
        ),
        (
            "m7_unpublish_media",
            command(112, C::UnpublishMedia(UnpublishMedia { media_id: 7 })),
        ),
        (
            "m7_subscribe_media",
            command(113, C::SubscribeMedia(SubscribeMedia { media_id: 7 })),
        ),
        (
            "m7_answer_media",
            command(
                114,
                C::AnswerMedia(AnswerMedia {
                    subscription_id: 8,
                    sdp_answer: M7_SECRETS[3].to_owned(),
                }),
            ),
        ),
        (
            "m7_unsubscribe_media",
            command(
                115,
                C::UnsubscribeMedia(UnsubscribeMedia { subscription_id: 8 }),
            ),
        ),
        (
            "m7_media_published",
            env(
                110,
                false,
                Body::CommandResult(CommandResult {
                    kind: Some(command_result::Kind::MediaPublished(MediaPublished {
                        media_id: 7,
                        sdp_answer: M7_SECRETS[1].to_owned(),
                    })),
                }),
            ),
        ),
        (
            "m7_media_offer",
            env(
                113,
                false,
                Body::CommandResult(CommandResult {
                    kind: Some(command_result::Kind::MediaOffer(MediaOffer {
                        subscription_id: 8,
                        media_id: 7,
                        sdp_offer: M7_SECRETS[2].to_owned(),
                    })),
                }),
            ),
        ),
        (
            "m7_turn_credentials_request",
            env(
                116,
                false,
                Body::Request(Request {
                    kind: Some(request::Kind::TurnCredentials(TurnCredentialsRequest {})),
                }),
            ),
        ),
        (
            "m7_turn_credentials",
            env(
                116,
                true,
                Body::Response(Response {
                    kind: Some(response::Kind::TurnCredentials(TurnCredentials {
                        urls: vec![M7_SECRETS[4].to_owned()],
                        username: M7_SECRETS[5].to_owned(),
                        password: M7_SECRETS[6].to_owned(),
                        expires_at: 1_800_000_000,
                    })),
                }),
            ),
        ),
        (
            "m7_event_media_track_added",
            env(
                0,
                false,
                Body::Event(Event {
                    seq: 710,
                    kind: Some(event::Kind::MediaTrackAdded(MediaTrackAdded {
                        track: Some(media_track()),
                    })),
                }),
            ),
        ),
        (
            "m7_event_media_track_removed",
            env(
                0,
                false,
                Body::Event(Event {
                    seq: 711,
                    kind: Some(event::Kind::MediaTrackRemoved(MediaTrackRemoved {
                        media_id: 7,
                    })),
                }),
            ),
        ),
        (
            "m7_media_ended_track",
            env(
                0,
                false,
                Body::Ephemeral(Ephemeral {
                    kind: Some(ephemeral::Kind::MediaEnded(MediaEnded {
                        target: Some(media_ended::Target::MediaId(7)),
                        reason: MediaEndReason::Moderation.into(),
                    })),
                }),
            ),
        ),
        (
            "m7_media_ended_subscription",
            env(
                0,
                false,
                Body::Ephemeral(Ephemeral {
                    kind: Some(ephemeral::Kind::MediaEnded(MediaEnded {
                        target: Some(media_ended::Target::SubscriptionId(8)),
                        reason: MediaEndReason::TrackEnded.into(),
                    })),
                }),
            ),
        ),
        (
            "m7_resync_media_tracks",
            env(
                0,
                false,
                Body::Resync(Snapshot {
                    seq: 712,
                    media_tracks: vec![media_track()],
                    ..Snapshot::default()
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
                        personal_last_seq: None,
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
                    mls_external_sender: None,
                    push_info: None,
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
                    mls_external_sender: None,
                    push_info: None,
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
                    media_tracks: vec![],
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
    .chain(m7_media_examples())
    .chain(m8_examples())
    .chain(m8_wire_b_examples())
    .chain(m9_examples())
    .chain(m10_examples())
    .chain(m11_examples())
    .chain(m11_mls_examples())
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
    assert_eq!(MINOR_VERSION, 11);
    assert_eq!(SUPPORTED_MINORS, [11, 10]);
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
        .chain(M7_SECRETS)
        .chain(M10_SECRETS)
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
                mls_epoch: None,
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
        mls_epoch: None,
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
        mls_epoch: None,
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
        mls_epoch: None,
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
            mls_epoch: None,
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
    // M7 (§ 6.14): an open join carries nothing to hide.
    assert_eq!(
        format!(
            "{:?}",
            Redeem {
                code: Some(redeem::Code::OpenJoin(OpenJoin {})),
            }
        ),
        "Redeem { code: Some(OpenJoin(OpenJoin)) }"
    );
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

/// § 6.6 "Privacy and logs": SDP (addresses, ports, ICE credentials) and
/// TURN credentials travel on the wire but `Debug` shows their lengths only,
/// decoded from bytes as a peer would send them; the ids and enums still show.
#[test]
fn media_sdp_and_turn_credentials_are_only_redacted_in_debug() {
    for (name, env) in m7_media_examples() {
        let bytes = env.encode_to_vec();
        let decoded = Envelope::decode(bytes.as_slice()).unwrap();
        let shown = format!("{decoded:?}");
        for secret in M7_SECRETS {
            assert!(!shown.contains(secret), "{name}: {secret} in {shown}");
        }
        let carried: Vec<_> = M7_SECRETS
            .iter()
            .filter(|s| bytes.windows(s.len()).any(|w| w == s.as_bytes()))
            .collect();
        let expected = match name {
            "m7_publish_media" | "m7_publish_media_camera" => vec![&M7_SECRETS[0]],
            "m7_answer_media" => vec![&M7_SECRETS[3]],
            "m7_media_published" => vec![&M7_SECRETS[1]],
            "m7_media_offer" => vec![&M7_SECRETS[2]],
            "m7_turn_credentials" => M7_SECRETS[4..].iter().collect(),
            _ => vec![],
        };
        assert_eq!(carried, expected, "{name}: on the wire");
        for secret in carried {
            assert!(
                shown.contains(&format!("<{} bytes>", secret.len())),
                "{name}: {shown}"
            );
        }
    }
    let shown = |name: &str| {
        let (_, env) = m7_media_examples()
            .into_iter()
            .find(|(n, _)| *n == name)
            .unwrap();
        format!("{env:?}")
    };
    assert!(shown("m7_publish_media").contains("kind: Screen"));
    assert!(shown("m7_publish_media_camera").contains("kind: Camera"));
    assert!(shown("m7_answer_media").contains("subscription_id: 8"));
    assert!(shown("m7_media_published").contains("media_id: 7"));
    let offer = shown("m7_media_offer");
    assert!(offer.contains("subscription_id: 8") && offer.contains("media_id: 7"));
    assert!(shown("m7_turn_credentials").contains("expires_at: 1800000000"));
    // A kind from a newer peer shows its number.
    let newer = PublishMedia {
        kind: 99,
        sdp_offer: String::new(),
    };
    assert!(format!("{newer:?}").contains("Unknown(99)"), "{newer:?}");
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
    // Every M7 media command and request kind is minor 7 (§ 6.6, § 6.7
    // "Minor 7"); replies, responses, events, ephemerals and the snapshot are
    // server-sent.
    let mut media_kinds = 0;
    for (name, env) in m7_media_examples() {
        let body = env.body.unwrap();
        let expected = match &body {
            Body::Command(_) | Body::Request(_) => 7,
            Body::CommandResult(_) | Body::Response(_) | Body::Resync(_) => 2,
            _ => 1,
        };
        assert_eq!(minor_of(&body), expected, "{name}");
        media_kinds += usize::from(expected == 7);
    }
    assert_eq!(
        media_kinds,
        6 + 1,
        "every M7 media command and request kind has an example"
    );
    // Every M8 command and request kind is minor 8 (§ 6.15, § 6.7 "Minor
    // 8"); `set_voice_state` only gained a field, which the session gates on
    // its own; the rest is server-sent or the handshake.
    let mut m8_kinds = 0;
    for (name, env) in m8_examples() {
        let body = env.body.unwrap();
        let expected = match (&body, name) {
            (_, "m8_set_voice_state_receiving") => 4,
            (Body::Command(_) | Body::Request(_), _) => 8,
            (Body::CommandResult(_) | Body::Response(_), _) => 2,
            _ => 1,
        };
        assert_eq!(minor_of(&body), expected, "{name}");
        m8_kinds += usize::from(expected == 8);
    }
    assert_eq!(
        m8_kinds,
        3 + 1,
        "every M8 command and request kind has an example"
    );
    // So is every wire-B kind; the event, the ephemeral and the webhook
    // fields of `Message` are server-sent, kept from minor 7 by the session
    // (§ 6.7 "Minor 8").
    let mut m8b_kinds = 0;
    for (name, env) in m8_wire_b_examples() {
        let body = env.body.unwrap();
        let expected = match &body {
            Body::Command(_) | Body::Request(_) => 8,
            Body::CommandResult(_) | Body::Response(_) => 2,
            _ => 1,
        };
        assert_eq!(minor_of(&body), expected, "{name}");
        m8b_kinds += usize::from(expected == 8);
    }
    assert_eq!(
        m8b_kinds,
        4 + 2,
        "every M8 wire-B command and request kind has an example"
    );
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

#[test]
fn bot_seeds_signatures_and_names_are_only_redacted_in_debug() {
    for (name, env) in m8_examples() {
        let bytes = env.encode_to_vec();
        let decoded = Envelope::decode(bytes.as_slice()).unwrap();
        let shown = format!("{decoded:?}");
        for secret in M8_SECRETS {
            assert!(!shown.contains(secret), "{name}: {secret} in {shown}");
        }
        let carried: Vec<_> = M8_SECRETS
            .iter()
            .filter(|s| bytes.windows(s.len()).any(|w| w == s.as_bytes()))
            .collect();
        let expected: Vec<_> = match name {
            "m8_bot_created" => M8_SECRETS.iter().collect(),
            "m8_create_bot" | "m8_bot_list" => vec![&M8_SECRETS[1]],
            _ => vec![],
        };
        assert_eq!(carried, expected, "{name}: on the wire");
        for secret in carried {
            assert!(
                shown.contains(&format!("<{} bytes>", secret.len())),
                "{name}: {shown}"
            );
        }
    }
    // The bot credential shows its public key and only the signature's
    // length.
    let (_, auth) = m8_examples()
        .into_iter()
        .find(|(n, _)| *n == "m8_auth_bot")
        .unwrap();
    let shown = format!("{auth:?}");
    assert!(shown.contains("signature: <64 bytes>"), "{shown}");
    assert!(!shown.contains("90, 90"), "{shown}"); // 0x5a
    assert!(shown.contains("176, 176"), "{shown}"); // 0xb0: the key
}

#[test]
fn webhook_tokens_names_and_option_values_are_only_redacted_in_debug() {
    for (name, env) in m8_wire_b_examples() {
        let bytes = env.encode_to_vec();
        let decoded = Envelope::decode(bytes.as_slice()).unwrap();
        let shown = format!("{decoded:?}");
        for secret in M8B_SECRETS {
            assert!(!shown.contains(secret), "{name}: {secret} in {shown}");
        }
        // The text ones only: the two numbers are not on the wire as text.
        let carried: Vec<_> = M8B_SECRETS[..5]
            .iter()
            .filter(|s| bytes.windows(s.len()).any(|w| w == s.as_bytes()))
            .collect();
        let expected: Vec<_> = match name {
            "m8_webhook_created" => vec![&M8B_SECRETS[0], &M8B_SECRETS[1]],
            "m8_create_webhook" | "m8_webhook_list" | "m8_event_webhook_message" => {
                vec![&M8B_SECRETS[1]]
            }
            "m8_register_commands" | "m8_command_list" => {
                vec![&M8B_SECRETS[2], &M8B_SECRETS[3]]
            }
            "m8_invoke_command" | "m8_interaction" => vec![&M8B_SECRETS[4]],
            _ => vec![],
        };
        assert_eq!(carried, expected, "{name}: on the wire");
        // Option values are left out altogether (counted, below); the rest
        // shows by length.
        for secret in carried.into_iter().filter(|s| **s != M8B_SECRETS[4]) {
            assert!(
                shown.contains(&format!("<{} bytes>", secret.len())),
                "{name}: {shown}"
            );
        }
    }
    let shown = |name: &str| {
        let (_, env) = m8_wire_b_examples()
            .into_iter()
            .find(|(n, _)| *n == name)
            .unwrap();
        format!("{env:?}")
    };
    // An invocation shows its ids, the command's name and the number of
    // options, never their values.
    for name in ["m8_invoke_command", "m8_interaction"] {
        let shown = shown(name);
        assert!(shown.contains("name: \"roll\""), "{shown}");
        assert!(shown.contains("channel_id: 5"), "{shown}");
        assert!(shown.contains("options: <5 options>"), "{shown}");
        assert!(!shown.contains("-987654321"), "{shown}");
    }
    assert!(shown("m8_invoke_command").contains("bot_account_id: 120"));
    assert!(shown("m8_interaction").contains("invoker_id: 42"));
    // A registered set shows names and kinds, descriptions by length.
    let set = shown("m8_register_commands");
    assert!(
        set.contains("name: \"sides\"") && set.contains("kind: Integer"),
        "{set}"
    );
    // The webhook keeps its ids; a message's webhook id shows too.
    assert!(shown("m8_webhook_created").contains("id: 150"));
    assert!(shown("m8_event_webhook_message").contains("webhook_id: Some(150)"));
    // An option value shows its name and kind only.
    for value in option_values() {
        let shown = format!("{value:?}");
        assert!(
            shown.contains(&format!("name: \"{}\"", value.name)),
            "{shown}"
        );
        for secret in M8B_SECRETS {
            assert!(!shown.contains(secret), "{shown}");
        }
    }
    let text = format!("{:?}", option_values()[0]);
    assert!(text.contains("value: Some(\"Text\")"), "{text}");
    // A name that is not a command name (a peer's free text in its place)
    // shows by length only.
    let free = InvokeCommand {
        name: "Free Text Name".to_owned(),
        ..InvokeCommand::default()
    };
    let shown = format!("{free:?}");
    assert!(!shown.contains("Free Text"), "{shown}");
    assert!(shown.contains("name: <14 bytes>"), "{shown}");
    let long = CommandOptionValue {
        name: "a".repeat(33),
        value: None,
    };
    assert!(format!("{long:?}").contains("name: <33 bytes>"));
    // The bounds of the § 6.15 name form: 32 bytes show, an empty name and
    // capitals alone do not.
    let longest = CommandOptionValue {
        name: "a".repeat(32),
        value: None,
    };
    assert!(
        format!("{longest:?}").contains(&format!("name: \"{}\"", "a".repeat(32))),
        "{longest:?}"
    );
    let empty = CommandOptionValue::default();
    assert!(
        format!("{empty:?}").contains("name: <0 bytes>"),
        "{empty:?}"
    );
    let capitals = InvokeCommand {
        name: "Roll".to_owned(),
        ..InvokeCommand::default()
    };
    let shown = format!("{capitals:?}");
    assert!(
        !shown.contains("Roll") && shown.contains("name: <4 bytes>"),
        "{shown}"
    );
    // A kind from a newer peer shows its number.
    let newer = CommandOption {
        kind: 99,
        ..CommandOption::default()
    };
    assert!(format!("{newer:?}").contains("Unknown(99)"), "{newer:?}");
}

/// § 6.16: `delete_thread` is command 67 and minor 9; `thread_deleted` is event 30, sent by
/// the server (minor 1 as a body; the session keeps it from minor 8).
#[test]
fn m9_kinds_are_minor_9_at_their_numbers() {
    use yapsta_proto::minor_of;
    for (name, env) in m9_examples() {
        let bytes = env.encode_to_vec();
        let body = env.body.unwrap();
        let (expected, tag) = match &body {
            // Command (field 9 of the envelope) carrying kind 67.
            Body::Command(_) => (9, 67u64 << 3 | 2),
            // Event (field 7) carrying kind 30.
            _ => (1, 30u64 << 3 | 2),
        };
        assert_eq!(minor_of(&body), expected, "{name}");
        let mut varint = Vec::new();
        prost::encoding::encode_varint(tag, &mut varint);
        assert!(
            bytes.windows(varint.len()).any(|w| w == varint),
            "{name}: kind tag {tag} on the wire"
        );
    }
    assert_eq!(
        yapsta_proto::command_kind_name(&command::Kind::DeleteThread(DeleteThread::default())),
        "delete_thread"
    );
}

/// § 6.16: the management audit actions are 22–37, in the spec's order;
/// minor 11 (§ 6.17) adds 38.
#[test]
fn m9_audit_actions_are_pinned() {
    let names = [
        "ROLE_CREATE",
        "ROLE_UPDATE",
        "ROLE_MOVE",
        "ROLE_DELETE",
        "MEMBER_ROLE_ADD",
        "MEMBER_ROLE_REMOVE",
        "OVERWRITE_SET",
        "OVERWRITE_DELETE",
        "CHANNEL_CREATE",
        "CHANNEL_UPDATE",
        "CHANNEL_MOVE",
        "CHANNEL_DELETE",
        "INVITE_CREATE",
        "INVITE_REVOKE",
        "THREAD_DELETE",
        "TEMPLATE_APPLY",
    ];
    for (number, name) in (22..).zip(names) {
        let action = AuditAction::try_from(number).unwrap();
        assert_eq!(action.as_str_name(), format!("AUDIT_ACTION_{name}"));
    }
    assert_eq!(
        AuditAction::try_from(38).unwrap().as_str_name(),
        "AUDIT_ACTION_DM_MODE_CHANGED"
    );
    assert!(AuditAction::try_from(39).is_err());
}

/// § 6.7 "Minor 10": every M10 command (68–85) and request (19–20) is minor
/// 10, at the number § 6.17 and § 6.18 give it; `personal` and
/// `personal_snapshot` are envelope bodies 19 and 20.
#[test]
fn m10_kinds_are_minor_10_at_their_numbers() {
    use yapsta_proto::minor_of;
    let numbers: &[(&str, u64, &str)] = &[
        ("m10_open_dm", 68, "open_dm"),
        ("m10_create_group_dm", 69, "create_group_dm"),
        ("m10_add_dm_member", 70, "add_dm_member"),
        ("m10_remove_dm_member", 71, "remove_dm_member"),
        ("m10_leave_dm", 72, "leave_dm"),
        ("m10_update_dm", 73, "update_dm"),
        ("m10_send_dm_message", 74, "send_dm_message"),
        ("m10_edit_dm_message", 75, "edit_dm_message"),
        ("m10_delete_dm_message", 76, "delete_dm_message"),
        ("m10_add_dm_reaction", 77, "add_dm_reaction"),
        ("m10_remove_dm_reaction", 78, "remove_dm_reaction"),
        ("m10_mark_dm_read", 79, "mark_dm_read"),
        ("m10_block", 80, "block"),
        ("m10_unblock", 81, "unblock"),
        (
            "m10_set_notification_setting",
            82,
            "set_notification_setting",
        ),
        ("m10_register_push_web", 83, "register_push"),
        ("m10_register_push_relay", 83, "register_push"),
        ("m10_unregister_push", 84, "unregister_push"),
        ("m10_go_background", 85, "go_background"),
        ("m10_dm_history", 19, ""),
        ("m10_list_dms", 20, ""),
    ];
    let examples = m10_examples();
    // The third column is `command_kind_name`'s (empty for a request).
    for (name, number, kind_name) in numbers {
        let (_, env) = examples.iter().find(|(n, _)| n == name).expect(name);
        let body = env.body.clone().unwrap();
        assert_eq!(minor_of(&body), 10, "{name}");
        if let Body::Command(Command { kind: Some(kind) }) = &body {
            assert_eq!(yapsta_proto::command_kind_name(kind), *kind_name, "{name}");
        }
        // The kind's tag sits right after the Command (9) or Request (16)
        // field's length: decode the inner message and read its first key.
        let inner = match &body {
            Body::Command(c) => c.encode_to_vec(),
            Body::Request(r) => r.encode_to_vec(),
            _ => unreachable!("{name}"),
        };
        let (tag, _) = prost::encoding::decode_key(&mut inner.as_slice()).unwrap();
        assert_eq!(u64::from(tag), *number, "{name}");
    }
    for (name, tag) in [
        ("m10_personal_dm_updated", 19u32),
        ("m10_personal_snapshot", 20),
    ] {
        let (_, env) = examples.iter().find(|(n, _)| *n == name).unwrap();
        assert_eq!(minor_of(env.body.as_ref().unwrap()), 10, "{name}");
        let bytes = env.encode_to_vec();
        let (first, _) = prost::encoding::decode_key(&mut bytes.as_slice()).unwrap();
        assert_eq!(first, tag, "{name}");
        assert!(
            yapsta_proto::frame::carries_server_body(&bytes),
            "{name} is server-only"
        );
    }
}

/// § 6.17 "Content in logs": who DMs, blocks or mutes whom never shows in
/// `Debug`. Each id below is spelled so nothing else in the output contains it.
#[test]
fn debug_output_hides_who_dms_and_blocks_whom() {
    const WHO: u64 = 987_654_321;
    const DM: u64 = 876_543_219;
    let emoji = Some(EmojiRef {
        emoji: Some(emoji_ref::Emoji::CustomId(1)),
    });
    let values: [&dyn std::fmt::Debug; 15] = [
        &OpenDm {
            reserved_dm_id: None,
            commit: None,
            account_id: WHO,
        },
        &Block { account_id: WHO },
        &Unblock { account_id: WHO },
        &AddDmMember {
            commit: None,
            dm_id: 1,
            account_id: WHO,
        },
        &RemoveDmMember {
            dm_id: 1,
            account_id: WHO,
        },
        &DmReactionAdded {
            dm_id: 1,
            message_id: 2,
            emoji: emoji.clone(),
            account_id: WHO,
        },
        &DmReactionRemoved {
            dm_id: 1,
            message_id: 2,
            emoji,
            account_id: WHO,
        },
        &BlockUpdated {
            account_id: WHO,
            blocked: true,
        },
        &NotificationSetting {
            target: NotifyTarget::Dm.into(),
            target_id: DM,
            level: NotifyLevel::None.into(),
            muted_until: 0,
        },
        &Dm {
            encryption: 0,
            successor_dm_id: None,
            mls_group_id: vec![],
            id: 1,
            kind: DmKind::Group.into(),
            member_ids: vec![WHO, WHO + 1],
            name: String::new(),
            owner_id: WHO,
            created_at: 0,
        },
        &CreateGroupDm {
            reserved_dm_id: None,
            commit: None,
            account_ids: vec![WHO],
            name: None,
        },
        &PersonalSnapshot {
            seq: 1,
            dms: vec![],
            dm_read_states: vec![],
            blocked_account_ids: vec![WHO],
            notification_settings: vec![],
        },
        &StartTyping {
            channel_id: 0,
            thread_id: None,
            dm_id: Some(DM),
        },
        &Typing {
            channel_id: 0,
            thread_id: None,
            account_id: 1,
            dm_id: Some(DM),
        },
        &yapsta_proto::v1::Message {
            dm_id: Some(DM),
            ..Default::default()
        },
    ];
    let shown = values.map(|v| format!("{v:?}"));
    for out in &shown {
        assert!(!out.contains(&WHO.to_string()), "{out}");
        assert!(!out.contains(&DM.to_string()), "{out}");
        assert!(out.contains("<hidden>") || out.contains(" ids>"), "{out}");
    }
    // Lists show their length, and an absent DM id stays visibly absent.
    assert!(shown[9].contains("<2 ids>"), "{}", shown[9]);
    let channel_typing = format!(
        "{:?}",
        Typing {
            channel_id: 5,
            thread_id: None,
            account_id: 1,
            dm_id: None,
        }
    );
    assert!(channel_typing.contains("dm_id: None"), "{channel_typing}");
}

/// Minor 11 (§ 6.17, "DM modes"): the values are pinned, a mode prints by
/// name, and a newer value prints as `Unknown`, never a bare number.
#[test]
fn dm_mode_values_are_pinned_and_named() {
    assert_eq!(
        [
            DmMode::Unspecified as i32,
            DmMode::Off as i32,
            DmMode::Live as i32,
            DmMode::Stored as i32,
        ],
        [0, 1, 2, 3]
    );
    let shown = format!(
        "{:?}",
        Space {
            dm_mode: DmMode::Stored.into(),
            ..Space::default()
        }
    );
    assert!(shown.contains("dm_mode: Stored"), "{shown}");
    let shown = format!(
        "{:?}",
        Space {
            dm_mode: 97,
            ..Space::default()
        }
    );
    assert!(shown.contains("dm_mode: Unknown(97)"), "{shown}");
}

/// A minor-10 `Space` (no field 15) decodes as `UNSPECIFIED`, which a client
/// reads as `STORED`; field 15 is the only new bytes.
#[test]
fn a_space_without_dm_mode_decodes_as_unspecified() {
    let old = space().encode_to_vec();
    assert_eq!(Space::decode(old.as_slice()).unwrap().dm_mode, 0);
    let new = Space {
        dm_mode: DmMode::Off.into(),
        ..space()
    }
    .encode_to_vec();
    assert_eq!(new, [old.as_slice(), &[0x78, 0x01]].concat());
}

/// § 6.19: every MLS command and request kind and the `mls` body are minor
/// 11, so a minor-10 session that sends one is refused for its version
/// (§ 6.7); fields minor 11 adds to older kinds leave them at their minor.
#[test]
fn every_mls_kind_is_minor_11() {
    use yapsta_proto::minor_of;
    let mut kinds = 0;
    for (name, env) in m11_mls_examples() {
        let body = env.body.unwrap();
        let expected = match (&body, name) {
            (Body::Command(_), "m11_open_dm_with_commit")
            | (Body::Command(_), "m11_create_group_dm_with_commit")
            | (Body::Command(_), "m11_add_dm_member_with_commit")
            | (Body::Command(_), "m11_send_dm_ciphertext")
            | (Body::Personal(_), _) => 10,
            (Body::Command(_) | Body::Request(_) | Body::Mls(_), _) => {
                kinds += 1;
                11
            }
            _ => continue,
        };
        assert_eq!(minor_of(&body), expected, "{name}");
    }
    assert_eq!(kinds, 4 + 3 + 1, "every MLS command, request and body");
    assert!(
        yapsta_proto::frame::SERVER_ONLY_BODIES.contains(&21),
        "`mls` is a server's body"
    );
}

/// § 6.19 "Logs": no MLS message bytes, KeyPackages, group ids, or the
/// targets of device-list lookups and claims show in `Debug`.
#[test]
fn debug_output_redacts_mls_bytes_and_lookup_targets() {
    let planted = format!("{MLS_SECRET_BYTE}");
    for (name, env) in m11_mls_examples() {
        let shown = format!("{env:?}");
        assert!(!shown.contains(&planted), "{name}: {shown}");
    }
    let shown = format!(
        "{:?}",
        ClaimKeyPackagesRequest {
            account_id: 4_242_424
        }
    );
    assert!(!shown.contains("4242424"), "{shown}");
    let shown = format!(
        "{:?}",
        DeviceListsRequest {
            account_ids: vec![4_242_424]
        }
    );
    assert!(!shown.contains("4242424"), "{shown}");
}
