//! The wire surface is add-only (docs/ARCHITECTURE.md § 6.7). The committed
//! `wire_surface.txt` lists every message field and enum value (nested ones too)
//! with its number, type and oneof, and every reservation. A removed,
//! renumbered, retyped or moved line fails this test, unless it was retired
//! properly: removed, with its number and name reserved. An added line asks for
//! the file to be updated, so additions are reviewed.
//!
//! To record an addition: `YAPSTA_BLESS=1 cargo test -p yapsta-proto --test wire_surface`.
//! Blessing only ever adds lines: it refuses while anything was lost.

use std::collections::BTreeSet;

use prost::Message;
use prost_types::field_descriptor_proto::{Label, Type};
use prost_types::{DescriptorProto, EnumDescriptorProto, FileDescriptorSet};

const DESCRIPTORS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/yapsta_v1.bin"));
const COMMITTED: &str = include_str!("wire_surface.txt");
/// Messages whose Debug is hand-written to redact them (build.rs, src/debug.rs).
const REDACTED_DEBUG: &str = include_str!("../redacted_debug.txt");
/// Text and bytes fields that are safe to print: keys, signatures, the
/// challenge and ids, public values whose size the receiver checks before use.
/// Free text and signed bodies are redacted, whatever the sender is meant to
/// put there.
const PUBLIC_FIELDS: &[&str] = &[
    // Sniffed by the server from a fixed table (§ 6.5), never the client's.
    "yapsta.v1.Attachment.media_type",
    "yapsta.v1.DeviceCredential.account_pub",
    "yapsta.v1.DeviceCredential.device_pub",
    "yapsta.v1.DeviceCredential.signature",
    "yapsta.v1.DeviceEntry.device_pub",
    "yapsta.v1.Hello.challenge",
    "yapsta.v1.Hello.server_id",
    "yapsta.v1.SignedDeviceList.signature",
];

fn enum_lines(name: &str, e: &EnumDescriptorProto, out: &mut Vec<String>) {
    for v in &e.value {
        out.push(format!("enum {name}.{} = {}", v.name(), v.number()));
    }
    // Enum reserved ranges are inclusive; written half-open like messages'.
    for range in &e.reserved_range {
        out.push(format!(
            "reserved {name} {}..{}",
            range.start(),
            i64::from(range.end()) + 1
        ));
    }
    for reserved in &e.reserved_name {
        out.push(format!("reserved {name} {reserved}"));
    }
}

fn message_lines(name: &str, msg: &DescriptorProto, out: &mut Vec<String>) {
    out.push(format!("message {name}"));
    for field in &msg.field {
        let ty = match field.r#type() {
            Type::Message | Type::Enum => field.type_name().to_owned(),
            other => format!("{other:?}").to_lowercase(),
        };
        let label = match (field.label(), field.proto3_optional()) {
            (Label::Repeated, _) => "repeated",
            (_, true) => "optional",
            _ => "singular",
        };
        let oneof = match field.oneof_index {
            Some(i) if !field.proto3_optional() => {
                format!(" oneof {}", msg.oneof_decl[i as usize].name())
            }
            _ => String::new(),
        };
        out.push(format!(
            "field {name}.{} = {} {label} {ty}{oneof}",
            field.name(),
            field.number()
        ));
    }
    for range in &msg.reserved_range {
        out.push(format!(
            "reserved {name} {}..{}",
            range.start(),
            range.end()
        ));
    }
    for reserved in &msg.reserved_name {
        out.push(format!("reserved {name} {reserved}"));
    }
    for e in &msg.enum_type {
        enum_lines(&format!("{name}.{}", e.name()), e, out);
    }
    for nested in &msg.nested_type {
        message_lines(&format!("{name}.{}", nested.name()), nested, out);
    }
}

fn descriptors() -> FileDescriptorSet {
    FileDescriptorSet::decode(DESCRIPTORS).unwrap()
}

fn current() -> Vec<String> {
    let mut out = Vec::new();
    for file in &descriptors().file {
        for msg in &file.message_type {
            message_lines(&format!("{}.{}", file.package(), msg.name()), msg, &mut out);
        }
        for e in &file.enum_type {
            enum_lines(&format!("{}.{}", file.package(), e.name()), e, &mut out);
        }
    }
    out.sort();
    out
}

/// A field or enum value line that was retired: its number and its name are
/// both reserved in `now`.
fn retired(line: &str, now: &BTreeSet<&str>) -> bool {
    let Some(rest) = line
        .strip_prefix("field ")
        .or_else(|| line.strip_prefix("enum "))
    else {
        return false;
    };
    let Some((path, tail)) = rest.split_once(" = ") else {
        return false;
    };
    let number = tail.split(' ').next().unwrap_or_default();
    let (Some((owner, name)), Ok(number)) = (path.rsplit_once('.'), number.parse::<i32>()) else {
        return false;
    };
    let number_reserved = now.iter().any(|l| {
        l.strip_prefix(&format!("reserved {owner} "))
            .and_then(|r| r.split_once(".."))
            .and_then(|(a, b)| Some((a.parse::<i64>().ok()?, b.parse::<i64>().ok()?)))
            .is_some_and(|(a, b)| (a..b).contains(&i64::from(number)))
    });
    number_reserved && now.contains(format!("reserved {owner} {name}").as_str())
}

/// Lines `committed` has that `now` lost (and did not retire), and lines `now`
/// added.
fn compare<'a>(
    committed: &BTreeSet<&'a str>,
    now: &BTreeSet<&'a str>,
) -> (Vec<&'a str>, Vec<&'a str>) {
    let lost = committed
        .difference(now)
        .filter(|l| !retired(l, now))
        .copied()
        .collect();
    let added = now.difference(committed).copied().collect();
    (lost, added)
}

fn indented(lines: &[&str]) -> String {
    lines
        .iter()
        .map(|l| format!("  {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_wire_surface_only_grows() {
    let current = current();
    let now: BTreeSet<&str> = current.iter().map(String::as_str).collect();
    let committed: BTreeSet<&str> = COMMITTED.lines().filter(|l| !l.is_empty()).collect();
    let (lost, added) = compare(&committed, &now);
    assert!(
        lost.is_empty(),
        "the wire surface lost or changed these lines (§ 6.7 forbids it):\n{}",
        indented(&lost)
    );
    #[allow(
        clippy::disallowed_methods,
        reason = "a test-only switch to record additions"
    )]
    if std::env::var_os("YAPSTA_BLESS").is_some() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/wire_surface.txt");
        std::fs::write(path, current.join("\n") + "\n").unwrap();
        return;
    }
    assert!(
        added.is_empty(),
        "new wire surface; review it and record it in tests/wire_surface.txt (YAPSTA_BLESS=1):\n{}",
        indented(&added)
    );
}

#[test]
fn the_retirement_rule() {
    let field = "field yapsta.v1.M.old = 2 singular bool";
    let value = "enum yapsta.v1.E.E_OLD = 3";
    let set = |lines: &[&'static str]| lines.iter().copied().collect::<BTreeSet<_>>();
    let committed = set(&[field, value]);
    for (now, retired_ok) in [
        (
            set(&[
                "reserved yapsta.v1.M 2..3",
                "reserved yapsta.v1.M old",
                "reserved yapsta.v1.E 3..4",
                "reserved yapsta.v1.E E_OLD",
            ]),
            true,
        ),
        // The number only, the name only, or another number: not retired.
        (
            set(&["reserved yapsta.v1.M 2..3", "reserved yapsta.v1.E 3..4"]),
            false,
        ),
        (
            set(&["reserved yapsta.v1.M old", "reserved yapsta.v1.E E_OLD"]),
            false,
        ),
        (
            set(&[
                "reserved yapsta.v1.M 3..4",
                "reserved yapsta.v1.M old",
                "reserved yapsta.v1.E 4..5",
                "reserved yapsta.v1.E E_OLD",
            ]),
            false,
        ),
        // Reserved just below: the range end is exclusive.
        (
            set(&[
                "reserved yapsta.v1.M 1..2",
                "reserved yapsta.v1.M old",
                "reserved yapsta.v1.E 2..3",
                "reserved yapsta.v1.E E_OLD",
            ]),
            false,
        ),
        // Renumbered rather than retired.
        (
            set(&[
                "field yapsta.v1.M.old = 5 singular bool",
                "enum yapsta.v1.E.E_OLD = 4",
            ]),
            false,
        ),
    ] {
        let (lost, _) = compare(&committed, &now);
        assert_eq!(!lost.contains(&field), retired_ok, "{now:?}");
        assert_eq!(!lost.contains(&value), retired_ok, "{now:?}");
    }
}

fn walk_enums<'a>(msgs: &'a [DescriptorProto], out: &mut Vec<&'a EnumDescriptorProto>) {
    for msg in msgs {
        out.extend(&msg.enum_type);
        walk_enums(&msg.nested_type, out);
    }
}

#[test]
fn every_enum_starts_at_unspecified() {
    let set = descriptors();
    let mut enums = Vec::new();
    for file in &set.file {
        enums.extend(&file.enum_type);
        walk_enums(&file.message_type, &mut enums);
    }
    assert!(!enums.is_empty());
    for e in enums {
        let zero = e.value.iter().find(|v| v.number() == 0);
        assert!(
            zero.is_some_and(|v| v.name().ends_with("_UNSPECIFIED")),
            "{} has no *_UNSPECIFIED = 0",
            e.name()
        );
    }
}

#[test]
fn every_text_field_is_redacted_or_public() {
    let redacted: BTreeSet<&str> = REDACTED_DEBUG.lines().filter(|l| !l.is_empty()).collect();
    let mut unclassified = Vec::new();
    for line in current() {
        let Some(rest) = line.strip_prefix("field ") else {
            continue;
        };
        let (path, tail) = rest.split_once(" = ").unwrap();
        let ty = tail.split(' ').nth(2).unwrap();
        if ty != "string" && ty != "bytes" {
            continue;
        }
        let (message, _) = path.rsplit_once('.').unwrap();
        if !redacted.contains(message) && !PUBLIC_FIELDS.contains(&path) {
            unclassified.push(path.to_owned());
        }
    }
    assert!(
        unclassified.is_empty(),
        "text fields that a {{:?}} would print; redact their message \
         (redacted_debug.txt + src/debug.rs) or list them in PUBLIC_FIELDS:\n  {}",
        unclassified.join("\n  ")
    );
}

#[test]
fn nested_enums_and_enum_reservations_are_listed() {
    use prost_types::EnumValueDescriptorProto;
    use prost_types::enum_descriptor_proto::EnumReservedRange;

    let kind = EnumDescriptorProto {
        name: Some("Kind".to_owned()),
        value: vec![EnumValueDescriptorProto {
            name: Some("KIND_UNSPECIFIED".to_owned()),
            number: Some(0),
            ..Default::default()
        }],
        reserved_range: vec![
            EnumReservedRange {
                start: Some(3),
                end: Some(3),
            },
            EnumReservedRange {
                start: Some(5),
                end: Some(i32::MAX),
            },
        ],
        reserved_name: vec!["KIND_OLD".to_owned()],
        ..Default::default()
    };
    let msg = DescriptorProto {
        name: Some("Channel".to_owned()),
        enum_type: vec![kind],
        ..Default::default()
    };
    let mut lines = Vec::new();
    message_lines("yapsta.v1.Channel", &msg, &mut lines);
    assert_eq!(
        lines,
        [
            "message yapsta.v1.Channel",
            "enum yapsta.v1.Channel.Kind.KIND_UNSPECIFIED = 0",
            // Inclusive 3..=3, written half-open like message ranges.
            "reserved yapsta.v1.Channel.Kind 3..4",
            "reserved yapsta.v1.Channel.Kind 5..2147483648",
            "reserved yapsta.v1.Channel.Kind KIND_OLD",
        ]
    );
}

#[test]
fn the_redaction_lists_name_real_messages_and_fields() {
    let set = descriptors();
    let mut messages = Vec::new();
    fn walk<'a>(
        name: String,
        msg: &'a DescriptorProto,
        out: &mut Vec<(String, &'a DescriptorProto)>,
    ) {
        for nested in &msg.nested_type {
            walk(format!("{name}.{}", nested.name()), nested, out);
        }
        out.push((name, msg));
    }
    for file in &set.file {
        for msg in &file.message_type {
            walk(
                format!("{}.{}", file.package(), msg.name()),
                msg,
                &mut messages,
            );
        }
    }
    for listed in REDACTED_DEBUG.lines().filter(|l| !l.is_empty()) {
        let (_, msg) = messages
            .iter()
            .find(|(name, _)| name == listed)
            .unwrap_or_else(|| panic!("redacted_debug.txt names {listed}, which does not exist"));
        // prost generates no type for a map entry, so skip_debug would not
        // redact it: redact the message that holds the map instead.
        assert!(
            !msg.options.as_ref().is_some_and(|o| o.map_entry()),
            "{listed} is a map entry; redact its parent message"
        );
    }
    for public in PUBLIC_FIELDS {
        let (owner, field) = public.rsplit_once('.').unwrap();
        assert!(
            messages
                .iter()
                .any(|(name, msg)| name == owner && msg.field.iter().any(|f| f.name() == field)),
            "PUBLIC_FIELDS names {public}, which does not exist"
        );
    }
}

/// Every `Envelope` body field is placed on purpose as a server's or a
/// client's (§ 6.16): a server refuses a client frame carrying a
/// server-only body before decoding it, so a new body must say which it is.
#[test]
fn every_envelope_body_is_a_servers_or_a_clients() {
    use yapsta_proto::frame::{CLIENT_BODIES, SERVER_ONLY_BODIES};
    let set = descriptors();
    let envelope = set
        .file
        .iter()
        .flat_map(|f| &f.message_type)
        .find(|m| m.name() == "Envelope")
        .expect("Envelope");
    let bodies: BTreeSet<i32> = envelope
        .field
        .iter()
        .filter(|f| f.oneof_index.is_some())
        .map(|f| f.number())
        .collect();
    let placed: BTreeSet<i32> = SERVER_ONLY_BODIES
        .iter()
        .chain(CLIENT_BODIES.iter())
        .map(|&n| i32::try_from(n).unwrap())
        .collect();
    assert_eq!(
        placed.len(),
        SERVER_ONLY_BODIES.len() + CLIENT_BODIES.len(),
        "a body in both lists"
    );
    assert_eq!(bodies, placed, "every body field in exactly one list");
}
