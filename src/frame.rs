//! Frames (§ 6.1): a `u32` big-endian length, then that many bytes of
//! [`Envelope`]. The length is checked against the stream's limit before
//! anything is reserved or read, so a peer cannot make the receiver allocate
//! more than the limit. The bytes are then walked, still undecoded, for the
//! most heap they can decode to ([`decoded_bound`]), and that is held to the
//! stream's decoded limit: the encoded length alone does not bound memory.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use prost::Message;
use tokio_util::codec::{Decoder, Encoder};

use crate::v1::{Envelope, ErrorCode};
use crate::{
    MAX_CONTROL_DECODED, MAX_CONTROL_FRAME, MAX_REQUEST_DECODED, MAX_REQUEST_FRAME,
    MAX_RESTRICTED_DECODED,
};

pub use crate::bound::MAX_DEPTH;

/// `Envelope` body fields only a server ever sends (§ 6.16): `error`,
/// `hello`, `welcome`, `event`, `ephemeral`, `ack`, `resync`,
/// `command_result`, `response`, and from M10 `personal` and
/// `personal_snapshot` (§ 6.3). A server refuses a client frame carrying any
/// of them before decoding it.
pub const SERVER_ONLY_BODIES: [u32; 11] = [3, 4, 6, 7, 8, 10, 13, 15, 17, 19, 20];
/// `Envelope` body fields a client sends: `auth`, `set_presence`, `ping`,
/// `redeem`, `command`, `request`, `start_typing`. Every body field is in
/// exactly one of the two lists (a wire-surface test holds that), so a new
/// one is placed on purpose.
pub const CLIENT_BODIES: [u32; 7] = [5, 9, 11, 12, 14, 16, 18];

const PREFIX: usize = 4;
/// The most the decoder asks to reserve ahead of the bytes received. `BytesMut`
/// may round a reservation up, so the buffer stays within about twice the bytes
/// received plus this step: it grows with what arrives, never with a claim.
const RESERVE_STEP: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The declared or encoded length is over the stream's limit, or the
    /// frame's [`decoded_bound`] is over the stream's decoded limit (`len` is
    /// then that bound, and `max` the decoded limit).
    #[error("a frame of {len} bytes is over the {max}-byte limit")]
    TooLarge { len: u64, max: usize },
    /// The frame's bytes are not an `Envelope`.
    #[error("the frame does not decode")]
    Invalid,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl FrameError {
    /// The code to close the stream or connection with (§ 6.1), or `None` for
    /// an I/O error: the transport is gone and there is nothing to send. Never
    /// close with code 0 (a normal close) for an error, or the peer won't resume.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::TooLarge { .. } => Some(ErrorCode::TooLarge),
            Self::Invalid => Some(ErrorCode::Invalid),
            Self::Io(_) => None,
        }
    }
}

/// Encodes and decodes [`Envelope`] frames up to a limit.
#[derive(Debug, Clone, Copy)]
pub struct FrameCodec {
    max: usize,
    /// The decoding limit: `max`, or less while a server restricts a
    /// client (§ 6.16). Encoding always uses `max`.
    max_in: usize,
    /// The decoded limit ([`decoded_bound`]) for `max`, and for `max_in`.
    max_decoded: usize,
    max_decoded_in: usize,
    /// A server reading a client: frames carrying a server-only body are
    /// refused before they are decoded.
    from_client: bool,
    /// Set when the last frame was refused for a server-only body, so the
    /// reader can count it apart from one that does not decode.
    refused_server_body: bool,
}

impl FrameCodec {
    /// The control stream and the TCP fallback: 1 MiB, decoding to at most
    /// [`MAX_CONTROL_DECODED`].
    pub fn control() -> Self {
        Self::with_limit(MAX_CONTROL_FRAME).with_decoded_limit(MAX_CONTROL_DECODED)
    }

    /// A QUIC request stream: 16 MiB, decoding to at most
    /// [`MAX_REQUEST_DECODED`].
    pub fn request() -> Self {
        Self::with_limit(MAX_REQUEST_FRAME).with_decoded_limit(MAX_REQUEST_DECODED)
    }

    /// Frames of at most `max` bytes (the prefix not counted), capped at
    /// `u32::MAX`, the largest length the prefix can carry. They decode to
    /// at most 16 times `max` ([`decoded_bound`]) unless
    /// [`with_decoded_limit`](Self::with_decoded_limit) says otherwise.
    pub fn with_limit(max: usize) -> Self {
        let max = max.min(u32::MAX as usize);
        let max_decoded = max.saturating_mul(16);
        Self {
            max,
            max_in: max,
            max_decoded,
            max_decoded_in: max_decoded,
            from_client: false,
            refused_server_body: false,
        }
    }

    /// The same codec, refusing a frame whose [`decoded_bound`] is over
    /// `max` bytes (and, while restricted, over the lesser of `max` and
    /// [`MAX_RESTRICTED_DECODED`]).
    #[must_use]
    pub fn with_decoded_limit(self, max: usize) -> Self {
        let mut codec = Self {
            max_decoded: max,
            ..self
        };
        codec.restrict(self.restricted());
        codec
    }

    /// The decoded limit frames are read under now: the most heap a frame
    /// may decode to, by [`decoded_bound`].
    pub fn decoded_limit(&self) -> usize {
        self.max_decoded_in
    }

    /// A server's control stream, reading a client: 1 MiB, and a frame
    /// carrying a body only a server sends is `INVALID` before it is
    /// decoded (§ 6.16).
    pub fn server_control() -> Self {
        Self {
            from_client: true,
            ..Self::control()
        }
    }

    /// Whether the last refused frame carried a server-only body; clears
    /// the mark.
    pub fn take_refused_server_body(&mut self) -> bool {
        std::mem::take(&mut self.refused_server_body)
    }

    /// Whether frames are decoded under [`MAX_RESTRICTED_FRAME`](crate::MAX_RESTRICTED_FRAME).
    pub fn restricted(&self) -> bool {
        self.max_in < self.max
    }

    /// Restricts (or, with `false`, frees) what is decoded to
    /// [`MAX_RESTRICTED_FRAME`], decoding to at most
    /// [`MAX_RESTRICTED_DECODED`]: before `Welcome` and for a non-member
    /// (§ 6.16). Encoding keeps the full limit.
    pub fn restrict(&mut self, restricted: bool) {
        (self.max_in, self.max_decoded_in) = if restricted {
            (
                self.max.min(crate::MAX_RESTRICTED_FRAME),
                self.max_decoded.min(MAX_RESTRICTED_DECODED),
            )
        } else {
            (self.max, self.max_decoded)
        };
    }
}

/// Whether `body` (an encoded `Envelope`) carries a field only a server
/// sends. Walks the top-level tags only, skipping each value; a malformed
/// frame is left for the decoder to refuse.
pub fn carries_server_body(mut body: &[u8]) -> bool {
    use prost::encoding::{DecodeContext, decode_key, skip_field};
    while !body.is_empty() {
        let Ok((tag, wire_type)) = decode_key(&mut body) else {
            return false;
        };
        if SERVER_ONLY_BODIES.contains(&tag) {
            return true;
        }
        if skip_field(wire_type, tag, &mut body, DecodeContext::default()).is_err() {
            return false;
        }
    }
    false
}

/// The most heap an `Envelope` decoded from `body` (an encoded `Envelope`,
/// no length prefix) can hold, past the `Envelope` value itself, walked
/// before decoding and without allocating. It counts each string and bytes
/// value, and each repeated field's `Vec` at twice its entries (capacity
/// grows by doubling) times the size of an entry, through every nested
/// message (up to [`MAX_DEPTH`] deep). Fields this version does not know
/// count nothing: they are skipped when decoding.
///
/// `INVALID` ([`FrameError::Invalid`]) for bytes that would not decode as
/// the schema says, or that nest past [`MAX_DEPTH`].
///
/// [`FrameCodec`] refuses a frame over its decoded limit with this; a
/// receiver can also charge its memory budgets by it rather than by the
/// encoded length.
pub fn decoded_bound(body: &[u8]) -> Result<usize, FrameError> {
    crate::bound::decoded_bound(body)
        .map(|n| usize::try_from(n).unwrap_or(usize::MAX))
        .map_err(|_| FrameError::Invalid)
}

/// How many entries the field at `path` has in `body` (an encoded
/// `Envelope`), counted before decoding, so a receiver can hold a kind's
/// entry caps (commands per registration, options per command) before it
/// decodes anything.
///
/// `path` is field numbers from `Envelope` down: every number but the last
/// names a message field. Entries add up across occurrences of a singular
/// message (they merge when decoded); through a repeated message the count
/// is the most any one entry of it has. A packed run counts each value.
///
/// `INVALID` if `body` would not decode, or `path` does not name such a
/// chain of fields in this version's schema.
pub fn repeated_entries(body: &[u8], path: &[u32]) -> Result<usize, FrameError> {
    crate::bound::repeated_entries(body, path)
        .map(|n| usize::try_from(n).unwrap_or(usize::MAX))
        .map_err(|_| FrameError::Invalid)
}

impl Decoder for FrameCodec {
    type Item = Envelope;
    type Error = FrameError;

    /// A complete frame, or `None` until one has arrived. A body variant this
    /// version doesn't know (a newer peer's) decodes to `body: None`, and so do
    /// unknown `kind`/`credential`/`state` variants inside: callers answer
    /// `INVALID` or ignore them (§ 6.1), and never `unwrap()` them.
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Envelope>, FrameError> {
        let Some(prefix) = src.get(..PREFIX) else {
            return Ok(None);
        };
        let len = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
        if u64::from(len) > self.max_in as u64 {
            return Err(FrameError::TooLarge {
                len: len.into(),
                max: self.max_in,
            });
        }
        let len = len as usize;
        if src.len() < PREFIX + len {
            // Grow with the bytes that arrive, not with the claimed length: a
            // 4-byte prefix must not reserve the whole limit.
            src.reserve((PREFIX + len - src.len()).min(RESERVE_STEP));
            return Ok(None);
        }
        src.advance(PREFIX);
        let body = src.split_to(len);
        if self.from_client && carries_server_body(&body) {
            self.refused_server_body = true;
            return Err(FrameError::Invalid);
        }
        let bound = decoded_bound(&body)?;
        if bound > self.max_decoded_in {
            return Err(FrameError::TooLarge {
                len: bound as u64,
                max: self.max_decoded_in,
            });
        }
        Envelope::decode(body.freeze())
            .map(Some)
            .map_err(|_| FrameError::Invalid)
    }

    /// The peer finished its stream: a clean end between frames is `None`, but
    /// a cut-off prefix or body is the peer's malformed framing, `INVALID`, not
    /// a lost transport (the other direction may still be open to say so).
    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Envelope>, FrameError> {
        match self.decode(src)? {
            Some(env) => Ok(Some(env)),
            None if src.is_empty() => Ok(None),
            None => Err(FrameError::Invalid),
        }
    }
}

impl Encoder<&Envelope> for FrameCodec {
    type Error = FrameError;

    fn encode(&mut self, item: &Envelope, dst: &mut BytesMut) -> Result<(), FrameError> {
        self.prefix(item.encoded_len(), dst)?;
        item.encode(dst).map_err(|_| FrameError::Invalid)
    }
}

impl Encoder<Envelope> for FrameCodec {
    type Error = FrameError;

    fn encode(&mut self, item: Envelope, dst: &mut BytesMut) -> Result<(), FrameError> {
        self.encode(&item, dst)
    }
}

/// An [`Envelope`] encoded already (no length prefix): one frame written to
/// many streams is encoded once, and each stream copies its bytes. Cloning
/// shares them. They hold content: `Debug` shows their length only.
#[derive(Clone, PartialEq, Eq)]
pub struct Encoded(Bytes);

impl std::fmt::Debug for Encoded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Encoded")
            .field("len", &self.0.len())
            .finish()
    }
}

impl Encoded {
    pub fn of(envelope: &Envelope) -> Self {
        Self(Bytes::from(envelope.encode_to_vec()))
    }

    /// The encoded envelope, shared.
    pub fn bytes(&self) -> &Bytes {
        &self.0
    }
}

impl Encoder<Encoded> for FrameCodec {
    type Error = FrameError;

    /// The same frame as encoding the envelope, held to the same limit.
    fn encode(&mut self, item: Encoded, dst: &mut BytesMut) -> Result<(), FrameError> {
        self.prefix(item.0.len(), dst)?;
        dst.extend_from_slice(&item.0);
        Ok(())
    }
}

impl FrameCodec {
    /// Refuses a body of `len` bytes over the limit; else reserves the
    /// frame's room and writes its prefix.
    fn prefix(&self, len: usize, dst: &mut BytesMut) -> Result<(), FrameError> {
        if len > self.max {
            return Err(FrameError::TooLarge {
                len: len as u64,
                max: self.max,
            });
        }
        dst.reserve(PREFIX + len);
        // `len` fits: the limit is at most u32::MAX (`with_limit`).
        dst.put_u32(len as u32);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::{Ping, envelope::Body};

    fn ping(request_id: u32) -> Envelope {
        Envelope {
            request_id,
            last: true,
            body: Some(Body::Ping(Ping {})),
        }
    }

    /// An envelope encoded once writes the same frame as encoding it on
    /// the stream, and is held to the same limit.
    #[test]
    fn an_encoded_envelope_writes_the_same_frame() {
        let envelope = ping(7);
        let mut direct = BytesMut::new();
        FrameCodec::control()
            .encode(&envelope, &mut direct)
            .unwrap();
        let mut shared = BytesMut::new();
        let encoded = Encoded::of(&envelope);
        FrameCodec::control()
            .encode(encoded.clone(), &mut shared)
            .unwrap();
        assert_eq!(shared, direct);
        assert_eq!(encoded.bytes().len() + PREFIX, direct.len());

        // The limit is inclusive, as for an envelope.
        let len = encoded.bytes().len();
        let mut sink = BytesMut::new();
        assert!(
            FrameCodec::with_limit(len)
                .encode(encoded.clone(), &mut sink)
                .is_ok()
        );
        let over = FrameCodec::with_limit(len - 1).encode(encoded.clone(), &mut sink);
        assert!(matches!(over, Err(FrameError::TooLarge { .. })), "{over:?}");
        // Its `Debug` shows no byte of it.
        assert_eq!(format!("{encoded:?}"), format!("Encoded {{ len: {len} }}"));
    }

    #[test]
    fn a_frame_round_trips_and_partial_input_waits() {
        let mut codec = FrameCodec::control();
        let mut buf = BytesMut::new();
        codec.encode(ping(7), &mut buf).unwrap();
        let whole = buf.clone();

        // Byte by byte: nothing until the last byte arrives.
        let mut partial = BytesMut::new();
        for (i, b) in whole.iter().enumerate() {
            partial.put_u8(*b);
            let got = codec.decode(&mut partial).unwrap();
            assert_eq!(got.is_some(), i == whole.len() - 1, "byte {i}");
            if let Some(env) = got {
                assert_eq!(env, ping(7));
            }
        }
        assert!(partial.is_empty());
    }

    #[test]
    fn an_oversize_prefix_is_refused_before_reserving() {
        for (codec, len) in [
            (FrameCodec::control(), MAX_CONTROL_FRAME as u32 + 1),
            (FrameCodec::request(), MAX_REQUEST_FRAME as u32 + 1),
            (FrameCodec::control(), u32::MAX),
        ] {
            let mut codec = codec;
            let mut buf = BytesMut::with_capacity(8);
            buf.put_u32(len);
            let cap = buf.capacity();
            let err = codec.decode(&mut buf).unwrap_err();
            assert!(matches!(err, FrameError::TooLarge { .. }), "{err}");
            assert_eq!(err.code(), Some(ErrorCode::TooLarge));
            assert_eq!(buf.capacity(), cap, "reserved for a refused frame");
        }
    }

    #[test]
    fn a_claimed_length_reserves_only_a_step() {
        let mut codec = FrameCodec::request();
        let mut buf = BytesMut::new();
        buf.put_u32(MAX_REQUEST_FRAME as u32);
        buf.put_u8(0);
        assert_eq!(codec.decode(&mut buf).unwrap(), None);
        assert!(buf.capacity() < 2 * RESERVE_STEP, "{}", buf.capacity());
    }

    #[test]
    fn a_frame_at_the_limit_is_accepted() {
        let mut codec = FrameCodec::with_limit(64);
        let mut buf = BytesMut::new();
        buf.put_u32(64);
        // 64 bytes of field 1 (request_id) varints is not valid padding, so use
        // an unknown field: tag 99 length-delimited (a two-byte key), 61 bytes
        // of payload.
        buf.put_slice(&[0x9a, 0x06]);
        buf.put_u8(61);
        buf.put_bytes(0, 61);
        assert_eq!(codec.decode(&mut buf).unwrap(), Some(Envelope::default()));
    }

    #[test]
    fn garbage_is_invalid_not_a_panic() {
        let mut codec = FrameCodec::control();
        let mut buf = BytesMut::new();
        buf.put_u32(3);
        buf.put_slice(&[0xff, 0xff, 0xff]);
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(err, FrameError::Invalid));
        assert_eq!(err.code(), Some(ErrorCode::Invalid));
    }

    #[test]
    fn coalesced_frames_come_out_one_at_a_time() {
        let mut codec = FrameCodec::control();
        let mut buf = BytesMut::new();
        codec.encode(ping(1), &mut buf).unwrap();
        codec.encode(ping(2), &mut buf).unwrap();
        buf.put_slice(&[0, 0]); // the start of a third prefix
        assert_eq!(codec.decode(&mut buf).unwrap(), Some(ping(1)));
        assert_eq!(codec.decode(&mut buf).unwrap(), Some(ping(2)));
        assert_eq!(codec.decode(&mut buf).unwrap(), None);
        assert_eq!(&buf[..], &[0, 0]);
    }

    #[test]
    fn the_encoder_limit_is_inclusive() {
        let len = ping(7).encoded_len();
        let mut buf = BytesMut::new();
        FrameCodec::with_limit(len)
            .encode(ping(7), &mut buf)
            .unwrap();
        assert!(matches!(
            FrameCodec::with_limit(len - 1).encode(ping(7), &mut BytesMut::new()),
            Err(FrameError::TooLarge { .. })
        ));
    }

    #[test]
    fn random_input_never_panics() {
        // Deterministic xorshift: no fuzzing dependency, same inputs every run.
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut reached_decode = 0;
        for _ in 0..5_000 {
            let mut codec = FrameCodec::with_limit(256);
            // Mostly a prefix within the limit, so the body reaches
            // `Envelope::decode`; one in ten is random.
            let len = (next() % 257) as u32;
            let prefix = if next() % 10 == 0 { next() as u32 } else { len };
            let mut bytes = prefix.to_be_bytes().to_vec();
            bytes.extend((0..len).map(|_| next() as u8));
            let mut buf = BytesMut::new();
            for chunk in bytes.chunks((next() % 17 + 1) as usize) {
                buf.put_slice(chunk);
                match codec.decode(&mut buf) {
                    Ok(None) => {}
                    Ok(Some(_)) | Err(FrameError::Invalid) => {
                        reached_decode += 1;
                        break;
                    }
                    Err(FrameError::TooLarge { .. }) => break,
                    Err(e) => panic!("unexpected {e}"),
                }
            }
        }
        assert!(reached_decode > 4_000, "{reached_decode}");
    }

    #[test]
    fn a_frame_cut_off_at_eof_is_invalid() {
        let mut whole = BytesMut::new();
        FrameCodec::control().encode(ping(7), &mut whole).unwrap();
        // A cut-off prefix, a prefix alone, and a cut-off body.
        for cut in [2, 4, whole.len() - 1] {
            let mut buf = BytesMut::from(&whole[..cut]);
            let err = FrameCodec::control().decode_eof(&mut buf).unwrap_err();
            assert!(matches!(err, FrameError::Invalid), "cut {cut}: {err}");
            assert_eq!(err.code(), Some(ErrorCode::Invalid));
        }
        // A whole frame, then the start of another: the frame, then INVALID.
        let mut codec = FrameCodec::control();
        let mut buf = whole.clone();
        buf.extend_from_slice(&whole[..2]);
        assert_eq!(codec.decode_eof(&mut buf).unwrap(), Some(ping(7)));
        assert!(matches!(
            codec.decode_eof(&mut buf),
            Err(FrameError::Invalid)
        ));
    }

    #[test]
    fn a_clean_eof_ends_the_stream() {
        let mut codec = FrameCodec::control();
        let mut buf = BytesMut::new();
        codec.encode(ping(7), &mut buf).unwrap();
        // The last whole frame still comes out, then the end.
        assert_eq!(codec.decode_eof(&mut buf).unwrap(), Some(ping(7)));
        assert_eq!(codec.decode_eof(&mut buf).unwrap(), None);
    }

    #[test]
    fn an_io_error_has_no_close_code() {
        let err = FrameError::Io(std::io::ErrorKind::ConnectionReset.into());
        assert_eq!(err.code(), None);
    }

    #[test]
    fn a_limit_above_the_prefix_range_is_capped() {
        let codec = FrameCodec::with_limit(usize::MAX);
        assert_eq!(codec.max, u32::MAX as usize);
    }

    #[test]
    fn the_encoder_refuses_an_oversize_frame() {
        let mut codec = FrameCodec::with_limit(4);
        let mut buf = BytesMut::new();
        let big = ping(u32::MAX);
        assert!(matches!(
            codec.encode(&big, &mut buf),
            Err(FrameError::TooLarge { .. })
        ));
        assert!(buf.is_empty());
    }

    /// One frame's bytes: the prefix, then `body` as given.
    fn raw_frame(body: &[u8]) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u32(u32::try_from(body.len()).unwrap());
        buf.extend_from_slice(body);
        buf
    }

    /// An empty length-delimited field `tag`, its key encoded as a varint.
    fn empty_field(tag: u32) -> Vec<u8> {
        let mut out = Vec::new();
        prost::encoding::encode_key(tag, prost::encoding::WireType::LengthDelimited, &mut out);
        out.push(0);
        out
    }

    /// An `Envelope` whose `resync` (field 13) is `members` empty `Member`s,
    /// two bytes each on the wire (audit H2).
    fn member_packed(members: usize) -> Vec<u8> {
        let mut snapshot = Vec::with_capacity(members * 2);
        for _ in 0..members {
            // `Snapshot.members` (7), length 0.
            snapshot.extend_from_slice(&[(7 << 3) | 2, 0]);
        }
        let mut body = vec![(13 << 3) | 2];
        prost::encoding::encode_varint(snapshot.len() as u64, &mut body);
        body.extend(snapshot);
        body
    }

    #[test]
    fn a_restricted_codec_refuses_a_large_frame_on_its_prefix() {
        let mut codec = FrameCodec::server_control();
        codec.restrict(true);
        // About 1 MiB of empty members: refused on the prefix, nothing read.
        let mut buf = raw_frame(&member_packed(500_000));
        let before = buf.len();
        assert!(matches!(
            codec.decode(&mut buf),
            Err(FrameError::TooLarge { max, .. }) if max == crate::MAX_RESTRICTED_FRAME
        ));
        assert_eq!(buf.len(), before, "nothing consumed");
        // Freed, a frame past the restricted cap decodes again.
        codec.restrict(false);
        let mut padded = vec![1 << 3, 7];
        prost::encoding::encode_key(99, prost::encoding::WireType::LengthDelimited, &mut padded);
        prost::encoding::encode_varint(crate::MAX_RESTRICTED_FRAME as u64, &mut padded);
        padded.resize(padded.len() + crate::MAX_RESTRICTED_FRAME, 0);
        let mut buf = raw_frame(&padded);
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap().request_id, 7);
    }

    #[test]
    fn a_server_refuses_a_server_only_body_before_decoding_it() {
        let mut codec = FrameCodec::server_control();
        // The audit's frame, under 1 MiB: `resync` packed with empty
        // members. Decoded, it would expand to some 100 MiB of `Member`s.
        let mut buf = raw_frame(&member_packed(500_000));
        assert!(matches!(codec.decode(&mut buf), Err(FrameError::Invalid)));
        assert!(codec.take_refused_server_body(), "marked as a server body");
        assert!(!codec.take_refused_server_body(), "the mark is taken once");
        // Every server-only body, even empty, and one hidden behind other
        // fields (a later oneof field wins in protobuf).
        for tag in SERVER_ONLY_BODIES {
            let mut buf = raw_frame(&empty_field(tag));
            assert!(
                matches!(codec.decode(&mut buf), Err(FrameError::Invalid)),
                "field {tag}"
            );
            // A `request_id`, a `Ping` (11), then the server-only body.
            let mut hidden = vec![1 << 3, 7];
            hidden.extend(empty_field(11));
            hidden.extend(empty_field(tag));
            let mut buf = raw_frame(&hidden);
            assert!(
                matches!(codec.decode(&mut buf), Err(FrameError::Invalid)),
                "field {tag} after a Ping"
            );
        }
        // A client's bodies, and a field this version does not know, decode.
        let mut buf = BytesMut::new();
        codec.encode(&ping(3), &mut buf).unwrap();
        assert_eq!(codec.decode(&mut buf).unwrap(), Some(ping(3)));
        let mut buf = raw_frame(&empty_field(99));
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap().body, None);
        // A client's codec decodes what a server sends.
        let mut buf = raw_frame(&empty_field(13));
        assert!(FrameCodec::control().decode(&mut buf).unwrap().is_some());
    }

    #[test]
    fn the_largest_legal_auth_fits_the_restricted_cap() {
        use crate::v1::{Auth, ClientInfo, DeviceCredential, Resume, SignedDeviceList, auth};
        let auth = Auth {
            version: u32::MAX,
            credential: Some(auth::Credential::Device(DeviceCredential {
                account_pub: vec![0xff; 32],
                device_list: Some(SignedDeviceList {
                    body: vec![0xff; crate::identity::MAX_DEVICE_LIST_BODY],
                    signature: vec![0xff; 64],
                }),
                device_pub: vec![0xff; 32],
                signature: vec![0xff; 64],
            })),
            // Each the largest varint an enum value takes.
            capabilities: vec![i32::MIN; 64],
            client_info: Some(ClientInfo {
                name: "n".repeat(64),
                version: "v".repeat(64),
            }),
            presence: Some(i32::MIN),
            resume: Some(Resume {
                personal_last_seq: None,
                token: vec![0xff; 32],
                last_seq: u64::MAX,
            }),
        };
        let frame = Envelope {
            request_id: u32::MAX,
            last: true,
            body: Some(Body::Auth(auth)),
        };
        assert!(frame.encoded_len() < 18 * 1024, "{}", frame.encoded_len());
        let mut codec = FrameCodec::server_control();
        codec.restrict(true);
        let mut buf = BytesMut::new();
        FrameCodec::control().encode(&frame, &mut buf).unwrap();
        assert_eq!(codec.decode(&mut buf).unwrap(), Some(frame));
    }
}
