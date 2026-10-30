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
    }
}

fn space() -> Space {
    Space {
        owner_account_id: 42,
        name: "space-text".to_owned(),
        description: "description-text".to_owned(),
        rules: "rules-text".to_owned(),
        icon_id: Some(76),
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
                    versions: SUPPORTED_MINORS.to_vec(),
                    challenge: vec![1; 32],
                    capabilities: vec![],
                    space_public_info: Some(SpacePublicInfo {
                        name: "space-text".to_owned(),
                        description: "description-text".to_owned(),
                        rules: "rules-text".to_owned(),
                        icon_id: Some(76),
                        claimed: true,
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
                    kind: Some(event::Kind::MemberRemoved(MemberRemoved { account_id: 43 })),
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
    assert_eq!(MINOR_VERSION, 2);
    assert_eq!(SUPPORTED_MINORS, [2, 1]);
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
    for text in ["yapsta-cli", "0.1.0", "away"].iter().chain(M2_SECRETS) {
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
