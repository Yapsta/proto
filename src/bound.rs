//! The decoded-size bound (§ 6.1): a walk over an encoded `Envelope` that
//! says, before decoding it, the most heap the decoded value can hold. A
//! frame's encoded length does not bound that: an empty entry of a repeated
//! message field is two bytes on the wire and a whole struct once decoded.
//!
//! The walk follows a table of the schema that build.rs writes from the
//! `.proto` (`bound_schema.rs`): each message's Rust size and each field's
//! kind. It allocates nothing: the entries of each repeated field are counted
//! in a fixed array on the stack.

use prost::encoding::{DecodeContext, WireType, decode_key, decode_varint, skip_field};

/// How deep the walk follows nested messages. The schema has no recursive
/// message, so a frame this version decodes is never deeper than the schema
/// (a test holds the schema under this); deeper is refused as `INVALID`.
pub const MAX_DEPTH: usize = 32;

pub(crate) struct Message {
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "names the table's rows in tests")
    )]
    pub(crate) name: &'static str,
    /// `size_of` the generated Rust struct: what one entry of a repeated
    /// field of this message takes in its `Vec`.
    pub(crate) size: usize,
    /// Sorted by tag.
    pub(crate) fields: &'static [Field],
}

pub(crate) struct Field {
    pub(crate) tag: u32,
    pub(crate) kind: Kind,
    /// The field's counter, for a repeated field.
    pub(crate) slot: Option<usize>,
}

#[derive(Clone, Copy)]
pub(crate) enum Kind {
    /// A message: the index of its row.
    Message(usize),
    /// A string or bytes value.
    Bytes,
    /// A varint scalar or enum, and its size in Rust.
    Varint(usize),
    /// A fixed-width scalar of this many bytes, on the wire and in Rust.
    Fixed(usize),
}

include!(concat!(env!("OUT_DIR"), "/bound_schema.rs"));

/// The walk failed: bytes that do not decode as the schema says, or nesting
/// past [`MAX_DEPTH`]. The decoder refuses the frame as `INVALID`.
#[derive(Debug)]
pub(crate) struct Malformed;

type Walk<T> = Result<T, Malformed>;

impl Message {
    fn field(&self, tag: u32) -> Option<&Field> {
        self.fields
            .binary_search_by_key(&tag, |f| f.tag)
            .ok()
            .map(|i| &self.fields[i])
    }
}

/// The most a `Vec` of `n` entries pushed one at a time holds: capacity
/// grows by doubling from a minimum of at most 8, so it is never more than
/// `max(8, 2n)`, and that sum over pushes split between merged occurrences
/// still bounds the one `Vec` they fill.
fn vec_bytes(n: u64, entry: usize) -> u64 {
    if n == 0 {
        0
    } else {
        (2 * n).max(8).saturating_mul(entry as u64)
    }
}

/// A string or bytes value of `len` bytes: reserved exactly, at least 8.
fn bytes_heap(len: u64) -> u64 {
    if len == 0 { 0 } else { len.max(8) }
}

/// Takes a length-delimited value off `buf`.
fn take_delimited<'a>(buf: &mut &'a [u8]) -> Walk<&'a [u8]> {
    let len = decode_varint(buf).map_err(|_| Malformed)?;
    let len = usize::try_from(len).map_err(|_| Malformed)?;
    if len > buf.len() {
        return Err(Malformed);
    }
    let (value, rest) = buf.split_at(len);
    *buf = rest;
    Ok(value)
}

/// The entries in a packed run of scalars.
fn packed_entries(kind: Kind, run: &[u8]) -> Walk<u64> {
    match kind {
        // A varint ends at each byte without the continuation bit.
        Kind::Varint(_) => Ok(run.iter().filter(|b| **b & 0x80 == 0).count() as u64),
        Kind::Fixed(size) if run.len().is_multiple_of(size) => Ok((run.len() / size) as u64),
        _ => Err(Malformed),
    }
}

/// Whether `wire_type` is the one prost accepts for a single value of
/// `kind`.
fn plain_wire_type(kind: Kind, wire_type: WireType) -> bool {
    matches!(
        (kind, wire_type),
        (Kind::Message(_) | Kind::Bytes, WireType::LengthDelimited)
            | (Kind::Varint(_), WireType::Varint)
            | (Kind::Fixed(8), WireType::SixtyFourBit)
            | (Kind::Fixed(4), WireType::ThirtyTwoBit)
    )
}

/// The heap a decoded `message` of these bytes can hold, past its own
/// struct.
fn heap(mut buf: &[u8], message: &Message, depth: usize) -> Walk<u64> {
    if depth > MAX_DEPTH {
        return Err(Malformed);
    }
    let mut entries = [0u64; MAX_REPEATED];
    let mut total = 0u64;
    while !buf.is_empty() {
        let (tag, wire_type) = decode_key(&mut buf).map_err(|_| Malformed)?;
        let Some(field) = message.field(tag) else {
            // Unknown to this version: prost skips it and keeps nothing.
            skip_field(wire_type, tag, &mut buf, DecodeContext::default())
                .map_err(|_| Malformed)?;
            continue;
        };
        let packed = field.slot.is_some()
            && matches!(field.kind, Kind::Varint(_) | Kind::Fixed(_))
            && wire_type == WireType::LengthDelimited;
        if packed {
            let run = take_delimited(&mut buf)?;
            if let Some(slot) = field.slot {
                entries[slot] += packed_entries(field.kind, run)?;
            }
            continue;
        }
        if !plain_wire_type(field.kind, wire_type) {
            return Err(Malformed);
        }
        match field.kind {
            Kind::Message(index) => {
                let value = take_delimited(&mut buf)?;
                let inner = heap(value, &MESSAGES[index], depth + 1)?;
                total = total.saturating_add(inner);
            }
            Kind::Bytes => {
                let value = take_delimited(&mut buf)?;
                total = total.saturating_add(bytes_heap(value.len() as u64));
            }
            Kind::Varint(_) | Kind::Fixed(_) => {
                skip_field(wire_type, tag, &mut buf, DecodeContext::default())
                    .map_err(|_| Malformed)?;
            }
        }
        if let Some(slot) = field.slot {
            entries[slot] += 1;
        }
    }
    for field in message.fields {
        let Some(slot) = field.slot else { continue };
        let entry = match field.kind {
            Kind::Message(index) => MESSAGES[index].size,
            Kind::Bytes => size_of::<Vec<u8>>(),
            Kind::Varint(size) | Kind::Fixed(size) => size,
        };
        total = total.saturating_add(vec_bytes(entries[slot], entry));
    }
    Ok(total)
}

/// See [`crate::frame::decoded_bound`].
pub(crate) fn decoded_bound(body: &[u8]) -> Walk<u64> {
    heap(body, &MESSAGES[ENVELOPE], 0)
}

/// See [`crate::frame::repeated_entries`].
pub(crate) fn repeated_entries(body: &[u8], path: &[u32]) -> Walk<u64> {
    if path.is_empty() || path.len() > MAX_DEPTH {
        return Err(Malformed);
    }
    entries_in(body, &MESSAGES[ENVELOPE], path)
}

/// The value of `path` in one message instance: occurrences of the last
/// field summed, through singular messages (which merge, so their entries
/// add up) and the most of any one entry through a repeated message.
fn entries_in(mut buf: &[u8], message: &Message, path: &[u32]) -> Walk<u64> {
    let (&tag, rest) = path.split_first().ok_or(Malformed)?;
    let field = message.field(tag).ok_or(Malformed)?;
    let child = match (field.kind, rest.is_empty()) {
        (_, true) => None,
        (Kind::Message(index), false) => Some(&MESSAGES[index]),
        _ => return Err(Malformed),
    };
    // Below a repeated message, entries do not add up across occurrences.
    let most = child.is_some_and(|c| repeated_below(c, rest));
    let mut count = 0u64;
    while !buf.is_empty() {
        let (got, wire_type) = decode_key(&mut buf).map_err(|_| Malformed)?;
        if got != tag {
            skip_field(wire_type, got, &mut buf, DecodeContext::default())
                .map_err(|_| Malformed)?;
            continue;
        }
        let value = match child {
            Some(child) => {
                if wire_type != WireType::LengthDelimited {
                    return Err(Malformed);
                }
                entries_in(take_delimited(&mut buf)?, child, rest)?
            }
            None if field.slot.is_some()
                && matches!(field.kind, Kind::Varint(_) | Kind::Fixed(_))
                && wire_type == WireType::LengthDelimited =>
            {
                packed_entries(field.kind, take_delimited(&mut buf)?)?
            }
            None => {
                skip_field(wire_type, got, &mut buf, DecodeContext::default())
                    .map_err(|_| Malformed)?;
                1
            }
        };
        count = if most || (child.is_some() && field.slot.is_some()) {
            count.max(value)
        } else {
            count + value
        };
    }
    Ok(count)
}

/// Whether `path` from `message` steps through a repeated message before its
/// last field.
fn repeated_below(message: &Message, path: &[u32]) -> bool {
    let Some((&tag, rest)) = path.split_first() else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    match message.field(tag) {
        Some(Field {
            kind: Kind::Message(index),
            slot,
            ..
        }) => slot.is_some() || repeated_below(&MESSAGES[*index], rest),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The deepest chain of nested messages in the schema, from `index`.
    fn depth(index: usize, seen: &mut Vec<usize>) -> usize {
        assert!(
            !seen.contains(&index),
            "{} is recursive",
            MESSAGES[index].name
        );
        seen.push(index);
        let deepest = MESSAGES[index]
            .fields
            .iter()
            .filter_map(|f| match f.kind {
                Kind::Message(i) => Some(1 + depth(i, seen)),
                _ => None,
            })
            .max()
            .unwrap_or(0);
        seen.pop();
        deepest
    }

    #[test]
    fn the_schema_is_shallower_than_the_depth_cap() {
        let deepest = depth(ENVELOPE, &mut Vec::new());
        assert!(deepest < MAX_DEPTH, "{deepest}");
        assert_eq!(MESSAGES[ENVELOPE].name, "Envelope");
    }

    #[test]
    fn the_table_is_sorted_and_slots_are_distinct() {
        for message in MESSAGES {
            assert!(
                message.fields.windows(2).all(|w| w[0].tag < w[1].tag),
                "{}",
                message.name
            );
            let slots: Vec<_> = message.fields.iter().filter_map(|f| f.slot).collect();
            assert_eq!(
                slots,
                (0..slots.len()).collect::<Vec<_>>(),
                "{}",
                message.name
            );
        }
    }

    fn grow<T: Default>() {
        let entry = size_of::<T>();
        let mut v: Vec<T> = Vec::new();
        for n in 1..5000u64 {
            v.push(T::default());
            let held = (v.capacity() * entry) as u64;
            assert!(held <= vec_bytes(n, entry), "n {n}, entry {entry}");
        }
    }

    #[test]
    fn vec_bytes_bounds_doubling_growth() {
        grow::<u8>();
        grow::<u32>();
        grow::<Vec<u8>>();
        grow::<crate::v1::SlashCommand>();
        grow::<crate::v1::Envelope>();
    }
}
