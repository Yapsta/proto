//! The decoded-size bound (§ 6.1): frames whose decoded value would be many
//! times their encoded length are refused before they are decoded, and the
//! bound is never below what decoding actually holds.

use bytes::{BufMut, BytesMut};
use prost::Message;
use tokio_util::codec::{Decoder, Encoder};
use yapsta_proto::frame::{FrameCodec, FrameError, decoded_bound, repeated_entries};
use yapsta_proto::v1::{CommandOption, Envelope, SlashCommand, command, envelope::Body};
use yapsta_proto::{
    MAX_CONTROL_DECODED, MAX_CONTROL_FRAME, MAX_REQUEST_DECODED, MAX_REQUEST_FRAME,
    MAX_RESTRICTED_DECODED, MAX_RESTRICTED_FRAME,
};

const GOLDEN: &str = include_str!("golden.txt");

/// Field `tag`, length-delimited, holding `payload`.
fn field(tag: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 8);
    prost::encoding::encode_key(tag, prost::encoding::WireType::LengthDelimited, &mut out);
    prost::encoding::encode_varint(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}

/// `entries` empty values of field `tag`: two bytes each on the wire.
fn empties(tag: u32, entries: usize) -> Vec<u8> {
    field(tag, &[]).repeat(entries)
}

/// The most entries for which `wrap(empties)` stays within `limit` bytes.
fn fill(limit: usize, wrap: impl Fn(usize) -> Vec<u8>) -> Vec<u8> {
    let (mut lo, mut hi) = (0, limit);
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if wrap(mid).len() <= limit {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    wrap(lo)
}

/// `Envelope.command` (14) → `Command.register_commands` (63) →
/// `RegisterCommands.commands` (1) of empty `SlashCommand`s.
fn empty_commands(limit: usize) -> Vec<u8> {
    fill(limit, |n| field(14, &field(63, &empties(1, n))))
}

/// One `SlashCommand` whose `options` (3) are empty `CommandOption`s.
fn empty_options(limit: usize) -> Vec<u8> {
    fill(limit, |n| field(14, &field(63, &field(1, &empties(3, n)))))
}

/// `Envelope.resync` (13) of empty `Snapshot.members` (7).
fn empty_members(limit: usize) -> Vec<u8> {
    fill(limit, |n| field(13, &empties(7, n)))
}

fn frame(body: &[u8]) -> BytesMut {
    let mut buf = BytesMut::new();
    buf.put_u32(u32::try_from(body.len()).unwrap());
    buf.extend_from_slice(body);
    buf
}

/// The `Vec` heap decoding `body` holds for the registration's commands and
/// their options: a floor the bound must not be under.
fn commands_heap(body: &[u8]) -> usize {
    let env = Envelope::decode(body).unwrap();
    let Some(Body::Command(c)) = env.body else {
        panic!("not a command")
    };
    let Some(command::Kind::RegisterCommands(r)) = c.kind else {
        panic!("not register_commands")
    };
    let options: usize = r
        .commands
        .iter()
        .map(|c| c.options.capacity() * size_of::<CommandOption>())
        .sum();
    r.commands.capacity() * size_of::<SlashCommand>() + options
}

fn refused(mut codec: FrameCodec, body: &[u8], limit: usize) {
    let mut buf = frame(body);
    match codec.decode(&mut buf) {
        Err(FrameError::TooLarge { len, max }) => {
            assert_eq!(max, limit);
            assert!(len > max as u64);
        }
        other => panic!("{} bytes: {other:?}", body.len()),
    }
}

fn restricted_server() -> FrameCodec {
    let mut codec = FrameCodec::server_control();
    codec.restrict(true);
    codec
}

/// Empty `SlashCommand`s filling the 32 KiB frame a client may send before
/// its `Welcome` decode to over a MiB.
#[test]
fn empty_commands_in_a_restricted_frame_are_refused() {
    let body = empty_commands(MAX_RESTRICTED_FRAME);
    assert!(body.len() > MAX_RESTRICTED_FRAME - 8);
    let bound = decoded_bound(&body).unwrap();
    let heap = commands_heap(&body);
    assert!(heap > 30 * body.len(), "the frame decodes to {heap} bytes");
    assert!(bound >= heap, "bound {bound} under the heap {heap}");
    refused(restricted_server(), &body, MAX_RESTRICTED_DECODED);
}

/// The same at 1 MiB, on a member's control stream.
#[test]
fn empty_commands_in_a_control_frame_are_refused() {
    let body = empty_commands(MAX_CONTROL_FRAME);
    let bound = decoded_bound(&body).unwrap();
    let heap = commands_heap(&body);
    assert!(heap > 30 * body.len(), "the frame decodes to {heap} bytes");
    assert!(bound >= heap, "bound {bound} under the heap {heap}");
    refused(FrameCodec::server_control(), &body, MAX_CONTROL_DECODED);
    let Some(Body::Command(c)) = Envelope::decode(body.as_slice()).unwrap().body else {
        panic!()
    };
    let Some(command::Kind::RegisterCommands(r)) = c.kind else {
        panic!()
    };
    assert_eq!(
        repeated_entries(&body, &[14, 63, 1]).unwrap(),
        r.commands.len(),
        "every empty command counted"
    );
}

/// One command with 1 MiB of empty options.
#[test]
fn empty_options_in_a_control_frame_are_refused() {
    let body = empty_options(MAX_CONTROL_FRAME);
    let bound = decoded_bound(&body).unwrap();
    let heap = commands_heap(&body);
    assert!(heap > 20 * body.len(), "the frame decodes to {heap} bytes");
    assert!(bound >= heap, "bound {bound} under the heap {heap}");
    refused(FrameCodec::server_control(), &body, MAX_CONTROL_DECODED);
    assert_eq!(repeated_entries(&body, &[14, 63, 1]).unwrap(), 1);
    assert!(repeated_entries(&body, &[14, 63, 1, 3]).unwrap() > 500_000);
}

/// A client holds a server's frames to the same bound: a control frame and
/// a request-stream reply of empty members.
#[test]
fn a_client_refuses_server_frames_over_the_bound() {
    refused(
        FrameCodec::control(),
        &empty_members(MAX_CONTROL_FRAME),
        MAX_CONTROL_DECODED,
    );
    refused(
        FrameCodec::request(),
        &empty_members(MAX_REQUEST_FRAME),
        MAX_REQUEST_DECODED,
    );
}

/// A reply of file bytes near the request-stream limit decodes: bytes decode
/// to their own size.
#[test]
fn a_full_size_blob_reply_decodes() {
    // `Response.blob` (2): `BlobData.data` (3).
    let data = vec![7u8; MAX_REQUEST_FRAME - 64];
    let body = field(17, &field(2, &field(3, &data)));
    assert!(body.len() <= MAX_REQUEST_FRAME);
    let bound = decoded_bound(&body).unwrap();
    assert!(bound >= data.len() && bound < data.len() + 1024, "{bound}");
    let mut buf = frame(&body);
    assert!(FrameCodec::request().decode(&mut buf).unwrap().is_some());
}

/// Every committed golden frame decodes under every codec's bound, and its
/// bound is a small multiple of its encoded length.
#[test]
fn golden_frames_are_within_every_bound() {
    for line in GOLDEN.lines().filter(|l| !l.is_empty()) {
        let (name, hex) = line.split_once(' ').unwrap();
        let body: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let bound = decoded_bound(&body).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(
            bound <= 64 * body.len().max(16),
            "{name}: {bound} for {}",
            body.len()
        );
        let env = Envelope::decode(body.as_slice()).unwrap();
        for codec in [FrameCodec::control(), FrameCodec::request(), {
            let mut c = FrameCodec::control();
            c.restrict(true);
            c
        }] {
            let mut codec = codec;
            let mut buf = frame(&body);
            assert_eq!(codec.decode(&mut buf).unwrap(), Some(env.clone()), "{name}");
        }
    }
}

/// Entries add up across occurrences of a singular message (they merge when
/// decoded), and a packed run counts each value.
#[test]
fn repeated_entries_counts_what_decoding_keeps() {
    // `command` twice, 3 and 4 commands: decoded, one registration of 7.
    let body = [
        field(14, &field(63, &empties(1, 3))),
        field(14, &field(63, &empties(1, 4))),
    ]
    .concat();
    assert_eq!(repeated_entries(&body, &[14, 63, 1]).unwrap(), 7);
    let Some(Body::Command(c)) = Envelope::decode(body.as_slice()).unwrap().body else {
        panic!()
    };
    let Some(command::Kind::RegisterCommands(r)) = c.kind else {
        panic!()
    };
    assert_eq!(r.commands.len(), 7);

    // Through a repeated message, the most any one entry has.
    let commands = [field(1, &empties(3, 2)), field(1, &empties(3, 5))].concat();
    let body = field(14, &field(63, &commands));
    assert_eq!(repeated_entries(&body, &[14, 63, 1, 3]).unwrap(), 5);

    // `Auth.capabilities` (5 → 3), packed: 64 varints of 1 to 10 bytes.
    let mut run = Vec::new();
    for i in 0..64i64 {
        prost::encoding::encode_varint(if i % 2 == 0 { 1 } else { i32::MIN as u64 }, &mut run);
    }
    let body = field(5, &field(3, &run));
    assert_eq!(repeated_entries(&body, &[5, 3]).unwrap(), 64);
    let Some(Body::Auth(auth)) = Envelope::decode(body.as_slice()).unwrap().body else {
        panic!()
    };
    assert_eq!(auth.capabilities.len(), 64);

    // A path that does not name message fields, and bytes that do not decode.
    assert!(repeated_entries(&body, &[]).is_err());
    assert!(repeated_entries(&body, &[5, 3, 1]).is_err());
    assert!(repeated_entries(&body, &[999]).is_err());
    assert!(repeated_entries(&[0x2a, 0x05], &[5, 3]).is_err());
}

/// The walk refuses what prost would refuse, and nothing it decodes.
#[test]
fn decoded_bound_agrees_with_decoding() {
    // A cut-off value, and a message field sent as a varint.
    assert!(decoded_bound(&[0x2a, 0x05, 0x00]).is_err());
    assert!(Envelope::decode([0x2a, 0x05, 0x00].as_slice()).is_err());
    assert!(decoded_bound(&[14 << 3, 0x01]).is_err());
    assert!(Envelope::decode([14 << 3, 0x01].as_slice()).is_err());
    // A field this version does not know counts nothing.
    assert_eq!(decoded_bound(&field(99, &[0; 1000])).unwrap(), 0);
    // Random bytes: whatever decodes has a bound.
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut decoded = 0;
    for _ in 0..20_000 {
        let len = (next() % 64) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        if let Ok(env) = Envelope::decode(bytes.as_slice()) {
            decoded += 1;
            assert!(decoded_bound(&bytes).is_ok(), "{bytes:02x?}");
            assert!(decoded_bound(&env.encode_to_vec()).is_ok());
        }
    }
    assert!(decoded > 100, "{decoded}");
}

/// A decoded limit set on a codec holds, restricted or not, and encoding
/// is unchanged by it.
#[test]
fn a_codec_holds_the_decoded_limit_it_is_given() {
    let body = empty_commands(4096);
    let bound = decoded_bound(&body).unwrap();
    let mut codec = FrameCodec::control().with_decoded_limit(bound);
    assert_eq!(codec.decoded_limit(), bound);
    assert!(codec.decode(&mut frame(&body)).unwrap().is_some());
    let mut codec = FrameCodec::control().with_decoded_limit(bound - 1);
    assert!(matches!(
        codec.decode(&mut frame(&body)),
        Err(FrameError::TooLarge { .. })
    ));
    let mut codec = FrameCodec::control();
    assert_eq!(codec.decoded_limit(), MAX_CONTROL_DECODED);
    codec.restrict(true);
    assert_eq!(codec.decoded_limit(), MAX_RESTRICTED_DECODED);
    let mut codec = codec.with_decoded_limit(1024);
    assert_eq!(codec.decoded_limit(), 1024, "restricted to the lesser");
    codec.restrict(false);
    assert_eq!(codec.decoded_limit(), 1024);
    assert_eq!(FrameCodec::request().decoded_limit(), MAX_REQUEST_DECODED);
    assert_eq!(FrameCodec::with_limit(64).decoded_limit(), 1024);
    let ping = Envelope {
        request_id: 1,
        last: true,
        body: Some(Body::Ping(Default::default())),
    };
    let mut out = BytesMut::new();
    FrameCodec::with_limit(64)
        .with_decoded_limit(0)
        .encode(&ping, &mut out)
        .unwrap();
    assert_eq!(
        FrameCodec::with_limit(64)
            .with_decoded_limit(0)
            .decode(&mut out)
            .unwrap(),
        Some(ping),
        "a frame with no heap fits a zero limit"
    );
}
