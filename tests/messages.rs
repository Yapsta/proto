//! Every message round-trips, and its bytes match a committed golden fixture
//! (`golden.txt`): a wire-stability guard beside `wire_surface.rs`. The client
//! and bot repos can check their encoders against the same fixtures.
//!
//! To update after an addition: `YAPSTA_BLESS=1 cargo test -p yapsta-proto --test messages`.

use prost::Message;
use yapsta_proto::v1::envelope::Body;
use yapsta_proto::v1::*;
use yapsta_proto::{MINOR_VERSION, WireCode};

const GOLDEN: &str = include_str!("golden.txt");

fn member() -> Member {
    Member {
        account_id: 42,
        joined_at: 1_800_000_000,
    }
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
                    code: ErrorCode::RateLimited.into(),
                    message: "slow down".to_owned(),
                    retry_after_ms: Some(1500),
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
                    versions: vec![MINOR_VERSION],
                    challenge: vec![1; 32],
                    capabilities: vec![],
                    space_public_info: Some(SpacePublicInfo {}),
                }),
            ),
        ),
        (
            "auth",
            env(
                0,
                false,
                Body::Auth(Auth {
                    version: MINOR_VERSION,
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
    ]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn every_message_round_trips_and_matches_its_golden_bytes() {
    let current: Vec<String> = examples()
        .iter()
        .map(|(name, env)| format!("{name} {}", hex(&env.encode_to_vec())))
        .collect();
    #[allow(
        clippy::disallowed_methods,
        reason = "a test-only switch to rewrite the fixtures"
    )]
    if std::env::var_os("YAPSTA_BLESS").is_some() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden.txt");
        std::fs::write(path, current.join("\n") + "\n").unwrap();
        return;
    }
    for (name, env) in examples() {
        let bytes = env.encode_to_vec();
        assert_eq!(Envelope::decode(bytes.as_slice()).unwrap(), env, "{name}");
        let golden = GOLDEN
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{name} ")))
            .unwrap_or_else(|| panic!("no golden bytes for {name}; YAPSTA_BLESS=1"));
        assert_eq!(hex(&bytes), golden, "{name}: the wire bytes changed");
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
fn an_unknown_error_code_is_an_error_not_a_normal_close() {
    let newer = Error {
        code: 14,
        message: String::new(),
        retry_after_ms: None,
    };
    assert_eq!(WireCode::of_error(&newer), WireCode::Unknown(14));
    assert!(!WireCode::of_error(&newer).is_normal_close());
    assert_eq!(WireCode::of_close(14), WireCode::Unknown(14));
    assert_eq!(WireCode::of_close(u64::MAX), WireCode::Unknown(i64::MAX));

    assert!(WireCode::of_close(0).is_normal_close());
    for code in [ErrorCode::SlowConsumer, ErrorCode::SessionReplaced] {
        assert_eq!(WireCode::of_close(code.close_code()), WireCode::Known(code));
        let error = Error {
            code: code.into(),
            message: String::new(),
            retry_after_ms: None,
        };
        assert_eq!(WireCode::of_error(&error), WireCode::Known(code));
    }
}
