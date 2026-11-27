//! `DmContent`, the plaintext inside an MLS DM's ciphertext (PROTOCOL.md
//! § 6.19 "Content"): each body round-trips and matches its committed bytes,
//! a body from a newer peer decodes as none (the receiver skips it), the
//! new clear kind is pinned, and `Debug` shows none of the content.

use prost::Message;
use yapsta_proto::v1::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every byte and text field filled with this byte or letter, so the
/// `Debug` test can look for it.
const PLANT: u8 = 0xe7;
const PLANT_TEXT: &str = "planted-text";

fn id() -> Vec<u8> {
    vec![PLANT; 16]
}

fn attachment() -> EncryptedAttachment {
    EncryptedAttachment {
        attachment_id: 81,
        key: vec![PLANT; 32],
        digest: vec![PLANT; 32],
        name: format!("{PLANT_TEXT}.png"),
        mime: format!("image/{PLANT_TEXT}"),
        size: 4_096,
        thumbnail: Some(EncryptedThumbnail {
            attachment_id: 82,
            key: vec![PLANT; 32],
            digest: vec![PLANT; 32],
            mime: format!("image/{PLANT_TEXT}"),
            size: 512,
        }),
    }
}

/// One example of each body, with its clear kind and committed bytes
/// (hex, the wire contract for every client).
fn examples() -> Vec<(&'static str, DmMessageKind, DmContent, &'static str)> {
    let content = |body| DmContent {
        id: id(),
        body: Some(body),
    };
    vec![
        (
            "text",
            DmMessageKind::Message,
            content(dm_content::Body::Text(DmText {
                text: PLANT_TEXT.to_owned(),
                reply_to: Some(vec![PLANT; 16]),
                attachments: vec![attachment()],
                mentions: vec![7, 8],
            })),
            TEXT,
        ),
        (
            "edit",
            DmMessageKind::Edit,
            content(dm_content::Body::Edit(DmEdit {
                target: vec![PLANT; 16],
                text: PLANT_TEXT.to_owned(),
            })),
            EDIT,
        ),
        (
            "delete",
            DmMessageKind::Delete,
            content(dm_content::Body::Delete(DmDelete {
                target: vec![PLANT; 16],
            })),
            DELETE,
        ),
        (
            "reaction",
            DmMessageKind::Reaction,
            content(dm_content::Body::Reaction(DmReaction {
                target: vec![PLANT; 16],
                emoji: Some(EmojiRef {
                    emoji: Some(emoji_ref::Emoji::Unicode(PLANT_TEXT.to_owned())),
                }),
                on: true,
            })),
            REACTION,
        ),
        (
            "group_name",
            DmMessageKind::GroupName,
            content(dm_content::Body::GroupName(DmGroupName {
                name: PLANT_TEXT.to_owned(),
            })),
            GROUP_NAME,
        ),
    ]
}

const TEXT: &str = "0a10e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e712f5010a0c706c616e7465642d74\
    6578741210e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e71ace0108511220e7e7e7e7\
    e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e71a20e7e7\
    e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e72210\
    706c616e7465642d746578742e706e672a12696d6167652f706c616e7465642d\
    746578743080203a5d08521220e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7\
    e7e7e7e7e7e7e7e7e7e7e7e7e71a20e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7\
    e7e7e7e7e7e7e7e7e7e7e7e7e7e7e72212696d6167652f706c616e7465642d74\
    65787428800422020708";
const EDIT: &str = "0a10e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e71a200a10e7e7e7e7e7e7e7e7e7e7\
    e7e7e7e7e7e7120c706c616e7465642d74657874";
const DELETE: &str = "0a10e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e722120a10e7e7e7e7e7e7e7e7e7e7\
    e7e7e7e7e7e7";
const REACTION: &str = "0a10e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e72a240a10e7e7e7e7e7e7e7e7e7e7\
    e7e7e7e7e7e7120e0a0c706c616e7465642d746578741801";
const GROUP_NAME: &str = "0a10e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7320e0a0c706c616e7465642d7465\
    7874";

#[test]
fn each_body_round_trips_and_matches_its_committed_bytes() {
    for (name, _, content, bytes) in examples() {
        let encoded = content.encode_to_vec();
        assert_eq!(hex(&encoded), bytes, "{name}");
        assert_eq!(DmContent::decode(&encoded[..]).unwrap(), content, "{name}");
    }
}

/// Each body's field number is its clear kind's value plus one (field 1 is
/// `id`): pinned, so neither moves.
#[test]
fn bodies_and_kinds_are_pinned() {
    assert_eq!(
        [
            DmMessageKind::Message as i32,
            DmMessageKind::Edit as i32,
            DmMessageKind::Delete as i32,
            DmMessageKind::Reaction as i32,
            DmMessageKind::GroupName as i32,
        ],
        [1, 2, 3, 4, 5]
    );
    for (name, kind, content, _) in examples() {
        let encoded = content.encode_to_vec();
        // `id` (tag 1, 16 bytes) comes first: 2 + 16 bytes, then the body's key.
        let key = encoded[18];
        assert_eq!(u32::from(key >> 3), kind as u32 + 1, "{name}");
    }
    let shown = format!(
        "{:?}",
        SendDmMessage {
            kind: DmMessageKind::GroupName.into(),
            ..SendDmMessage::default()
        }
    );
    assert!(shown.contains("kind: GroupName"), "{shown}");
}

/// A body a newer peer added decodes as no body, its `id` intact: the
/// receiver skips the message (§ 6.19 "Content").
#[test]
fn an_unknown_body_decodes_as_none() {
    let mut encoded = DmContent {
        id: id(),
        body: None,
    }
    .encode_to_vec();
    // Field 15, length-delimited, 3 bytes.
    encoded.extend_from_slice(&[0x7a, 0x03, 0x0a, 0x01, 0x41]);
    let decoded = DmContent::decode(&encoded[..]).unwrap();
    assert_eq!(decoded.id, id());
    assert!(decoded.body.is_none());
    // An emoji kind a newer peer added (EmojiRef field 3) is skipped the
    // same way: the reaction keeps its target and `on`, with no emoji.
    let mut encoded = vec![0x0a, 0x10];
    encoded.extend_from_slice(&[PLANT; 16]);
    encoded.extend_from_slice(&[0x12, 0x02, 0x18, 0x01, 0x18, 0x01]);
    let decoded = DmReaction::decode(&encoded[..]).unwrap();
    assert_eq!(decoded.target, vec![PLANT; 16]);
    assert!(decoded.on);
    assert!(decoded.emoji.unwrap().emoji.is_none());
}

/// No byte, text, name, type or mention of the content shows in `Debug`.
#[test]
fn debug_shows_none_of_the_content() {
    let planted = format!("{PLANT}");
    for (name, _, content, _) in examples() {
        let shown = format!("{content:?}");
        assert!(!shown.contains(&planted), "{name}: {shown}");
        assert!(!shown.contains(PLANT_TEXT), "{name}: {shown}");
        assert!(!shown.contains("png"), "{name}: {shown}");
        assert!(!shown.contains("image"), "{name}: {shown}");
    }
    let shown = format!(
        "{:?}",
        DmText {
            mentions: vec![4_242_424],
            ..DmText::default()
        }
    );
    assert!(!shown.contains("4242424"), "{shown}");
}
