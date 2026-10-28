//! The wire surface is add-only (docs/ARCHITECTURE.md § 6.7). The committed
//! `wire_surface.txt` lists every message field and enum value with its number,
//! type and oneof. A removed, renumbered, retyped or moved line fails this test;
//! an added line asks for the file to be updated, so additions are reviewed.
//!
//! To update after an addition: `YAPSTA_BLESS=1 cargo test -p yapsta-proto --test wire_surface`.

use std::collections::BTreeSet;

use prost::Message;
use prost_types::field_descriptor_proto::{Label, Type};
use prost_types::{DescriptorProto, FileDescriptorSet};

const DESCRIPTORS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/yapsta_v1.bin"));
const COMMITTED: &str = include_str!("wire_surface.txt");

fn message_lines(prefix: &str, msg: &DescriptorProto, out: &mut Vec<String>) {
    let name = format!("{prefix}{}", msg.name());
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
    for nested in &msg.nested_type {
        message_lines(&format!("{name}."), nested, out);
    }
}

fn current() -> Vec<String> {
    let set = FileDescriptorSet::decode(DESCRIPTORS).unwrap();
    let mut out = Vec::new();
    for file in &set.file {
        let pkg = format!("{}.", file.package());
        for msg in &file.message_type {
            message_lines(&pkg, msg, &mut out);
        }
        for e in &file.enum_type {
            for v in &e.value {
                out.push(format!(
                    "enum {pkg}{}.{} = {}",
                    e.name(),
                    v.name(),
                    v.number()
                ));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn the_wire_surface_only_grows() {
    let current = current();
    #[allow(
        clippy::disallowed_methods,
        reason = "a test-only switch to rewrite the snapshot"
    )]
    if std::env::var_os("YAPSTA_BLESS").is_some() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/wire_surface.txt");
        std::fs::write(path, current.join("\n") + "\n").unwrap();
        return;
    }
    let now: BTreeSet<&str> = current.iter().map(String::as_str).collect();
    let committed: BTreeSet<&str> = COMMITTED.lines().filter(|l| !l.is_empty()).collect();

    // A field may be retired: removed, with its number and name reserved.
    let retired = |line: &str| -> bool {
        let Some(rest) = line.strip_prefix("field ") else {
            return false;
        };
        let Some((path, tail)) = rest.split_once(" = ") else {
            return false;
        };
        let Some((msg, field)) = path.rsplit_once('.') else {
            return false;
        };
        let number: i32 = tail.split(' ').next().unwrap().parse().unwrap();
        let number_reserved = now.iter().any(|l| {
            l.strip_prefix(&format!("reserved {msg} "))
                .and_then(|r| r.split_once(".."))
                .is_some_and(|(a, b)| {
                    let (a, b): (i32, i32) = (a.parse().unwrap(), b.parse().unwrap());
                    (a..b).contains(&number)
                })
        });
        number_reserved && now.contains(format!("reserved {msg} {field}").as_str())
    };
    let lost: Vec<_> = committed.difference(&now).filter(|l| !retired(l)).collect();
    assert!(
        lost.is_empty(),
        "the wire surface lost or changed these lines (§ 6.7 forbids it):\n{}",
        lost.iter()
            .map(|l| format!("  {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let added: Vec<_> = now.difference(&committed).collect();
    assert!(
        added.is_empty(),
        "new wire surface; review it and update tests/wire_surface.txt (YAPSTA_BLESS=1):\n{}",
        added
            .iter()
            .map(|l| format!("  {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn every_enum_starts_at_unspecified() {
    let set = FileDescriptorSet::decode(DESCRIPTORS).unwrap();
    for file in &set.file {
        for e in &file.enum_type {
            let zero = e.value.iter().find(|v| v.number() == 0);
            assert!(
                zero.is_some_and(|v| v.name().ends_with("_UNSPECIFIED")),
                "{} has no *_UNSPECIFIED = 0",
                e.name()
            );
        }
    }
}
