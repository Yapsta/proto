//! Voice datagrams (docs/PROTOCOL.md § 6.4, § 6.10): the 16-byte header in
//! front of the Opus payload. Not protobuf: the layout is fixed byte by byte,
//! big-endian, and pinned by `tests/voice.rs`.
//!
//! ```text
//! 0      version (high nibble, = 1) | flags (low nibble: EOT 0x1, DTX 0x2)
//! 1      codec: 1 = opus-voice, 2 = opus-music
//! 2      route: 0 = channel, 1 = whisper, 2 = direct (reserved)
//! 3      key_id: 0 = none (reserved for E2EE)
//! 4..6   seq
//! 6..10  timestamp (48 kHz sample clock)
//! 10..14 ref: C→S own session_ref (route 0) | whisper list_id (route 1);
//!        S→C the sender's session_ref
//! 14..16 reserved
//! ```
//!
//! The payload is never decoded here or anywhere in the server.

use std::fmt;

use bytes::{BufMut, Bytes, BytesMut};

/// Length of the header.
pub const HEADER_LEN: usize = 16;

/// Largest datagram, header included (§ 6.4). The path's own maximum can be
/// smaller; the sender checks that one.
pub const MAX_DATAGRAM: usize = 1200;

/// The header version this crate speaks.
pub const VERSION: u8 = 1;

const EOT: u8 = 0x1;
const DTX: u8 = 0x2;
/// The flag bits that mean something; 0x4 and 0x8 are sent as 0 and ignored.
const KNOWN_FLAGS: u8 = EOT | DTX;

const REF: std::ops::Range<usize> = 10..14;

/// The codec of a datagram's payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// Opus, mono (1).
    OpusVoice,
    /// Opus, stereo (2).
    OpusMusic,
}

/// Where a datagram goes. Route 2 (direct) is reserved and refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// To the sender's voice channel (0).
    Channel,
    /// To a registered whisper list (1).
    Whisper,
}

/// A parsed header. Fields this version ignores (flag bits 0x4 and 0x8,
/// `reserved`) are not kept; `key_id` is always 0. Its `Debug` leaves out
/// `seq` and `timestamp`, which never go into a log (§ 6.10).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// End of transmission: the last frame of a burst.
    pub eot: bool,
    /// Discontinuous transmission: a comfort-noise or silence frame.
    pub dtx: bool,
    pub codec: Codec,
    pub route: Route,
    /// The sender's, wraps.
    pub seq: u16,
    /// The sender's 48 kHz sample clock, wraps.
    pub timestamp: u32,
    /// See the module docs: its meaning depends on the direction and route.
    pub r#ref: u32,
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            eot,
            dtx,
            codec,
            route,
            seq: _,
            timestamp: _,
            r#ref,
        } = self;
        f.debug_struct("Header")
            .field("eot", eot)
            .field("dtx", dtx)
            .field("codec", codec)
            .field("route", route)
            .field("ref", r#ref)
            .finish_non_exhaustive()
    }
}

/// Why a datagram was dropped. A counter label only: never logged with the
/// datagram's bytes (§ 6.4, § 7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    TooShort,
    TooLong,
    Version,
    Codec,
    Route,
    KeyId,
}

impl Reject {
    /// A fixed label for a drop counter.
    pub fn reason(self) -> &'static str {
        match self {
            Self::TooShort => "too_short",
            Self::TooLong => "too_long",
            Self::Version => "version",
            Self::Codec => "codec",
            Self::Route => "route",
            Self::KeyId => "key_id",
        }
    }
}

impl Header {
    /// Parses and validates a received datagram's header (§ 6.4 Validation).
    /// The payload is `&datagram[HEADER_LEN..]`. Never panics, whatever the
    /// input.
    pub fn parse(datagram: &[u8]) -> Result<Self, Reject> {
        if datagram.len() > MAX_DATAGRAM {
            return Err(Reject::TooLong);
        }
        let Some(h) = datagram.first_chunk::<HEADER_LEN>() else {
            return Err(Reject::TooShort);
        };
        if h[0] >> 4 != VERSION {
            return Err(Reject::Version);
        }
        let codec = match h[1] {
            1 => Codec::OpusVoice,
            2 => Codec::OpusMusic,
            _ => return Err(Reject::Codec),
        };
        let route = match h[2] {
            0 => Route::Channel,
            1 => Route::Whisper,
            _ => return Err(Reject::Route),
        };
        if h[3] != 0 {
            return Err(Reject::KeyId);
        }
        Ok(Self {
            eot: h[0] & EOT != 0,
            dtx: h[0] & DTX != 0,
            codec,
            route,
            seq: u16::from_be_bytes([h[4], h[5]]),
            timestamp: u32::from_be_bytes([h[6], h[7], h[8], h[9]]),
            r#ref: u32::from_be_bytes([h[10], h[11], h[12], h[13]]),
        })
    }

    /// The 16 header bytes, with `key_id`, the unused flag bits and
    /// `reserved` all 0.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut h = [0; HEADER_LEN];
        h[0] = VERSION << 4 | if self.eot { EOT } else { 0 } | if self.dtx { DTX } else { 0 };
        h[1] = match self.codec {
            Codec::OpusVoice => 1,
            Codec::OpusMusic => 2,
        };
        h[2] = match self.route {
            Route::Channel => 0,
            Route::Whisper => 1,
        };
        h[4..6].copy_from_slice(&self.seq.to_be_bytes());
        h[6..10].copy_from_slice(&self.timestamp.to_be_bytes());
        h[REF].copy_from_slice(&self.r#ref.to_be_bytes());
        h
    }

    /// A whole datagram: this header, then `payload`.
    pub fn datagram(&self, payload: &[u8]) -> Bytes {
        let mut out = BytesMut::with_capacity(HEADER_LEN + payload.len());
        out.put_slice(&self.encode());
        out.put_slice(payload);
        out.freeze()
    }
}

/// The copy of a received datagram the server forwards (§ 6.4): `ref`
/// rewritten to the sender's `session_ref`, the unused flag bits, `key_id`
/// (0 in any valid datagram) and `reserved` zeroed, so only the server can
/// ever give them a meaning, everything else (version, `EOT`, `DTX`, codec, route,
/// `seq`, `timestamp` and the payload) byte for byte. One copy per received
/// datagram, shared by every listener. Call it on a datagram that passed
/// [`Header::parse`]; `None` only for one shorter than a header.
pub fn forwarded(datagram: &[u8], sender_ref: u32) -> Option<Bytes> {
    if datagram.len() < HEADER_LEN {
        return None;
    }
    let mut out = BytesMut::from(datagram);
    out[0] &= 0xF0 | KNOWN_FLAGS;
    out[3] = 0;
    out[REF].copy_from_slice(&sender_ref.to_be_bytes());
    out[14..16].fill(0);
    Some(out.freeze())
}
