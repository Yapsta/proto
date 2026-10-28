//! Frames (§ 6.1): a `u32` big-endian length, then that many bytes of
//! [`Envelope`]. The length is checked against the stream's limit before
//! anything is reserved or read, so a peer cannot make the receiver allocate
//! more than the limit.

use bytes::{Buf, BufMut, BytesMut};
use prost::Message;
use tokio_util::codec::{Decoder, Encoder};

use crate::v1::{Envelope, ErrorCode};
use crate::{MAX_CONTROL_FRAME, MAX_REQUEST_FRAME};

const PREFIX: usize = 4;
/// At most this much is reserved ahead of the bytes received.
const RESERVE_STEP: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The declared or encoded length is over the stream's limit.
    #[error("a frame of {len} bytes is over the {max}-byte limit")]
    TooLarge { len: u64, max: usize },
    /// The frame's bytes are not an `Envelope`.
    #[error("the frame does not decode")]
    Invalid,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl FrameError {
    /// The code to close the stream or connection with (§ 6.1).
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::TooLarge { .. } => ErrorCode::TooLarge,
            Self::Invalid => ErrorCode::Invalid,
            Self::Io(_) => ErrorCode::Unspecified,
        }
    }
}

/// Encodes and decodes [`Envelope`] frames up to a limit.
#[derive(Debug, Clone, Copy)]
pub struct FrameCodec {
    max: usize,
}

impl FrameCodec {
    /// The control stream and the TCP fallback: 1 MiB.
    pub fn control() -> Self {
        Self::with_limit(MAX_CONTROL_FRAME)
    }

    /// A QUIC request stream: 16 MiB.
    pub fn request() -> Self {
        Self::with_limit(MAX_REQUEST_FRAME)
    }

    /// Frames of at most `max` bytes (the prefix not counted).
    pub fn with_limit(max: usize) -> Self {
        Self { max }
    }

    pub fn limit(&self) -> usize {
        self.max
    }
}

impl Decoder for FrameCodec {
    type Item = Envelope;
    type Error = FrameError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Envelope>, FrameError> {
        let Some(prefix) = src.get(..PREFIX) else {
            return Ok(None);
        };
        let len = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
        if u64::from(len) > self.max as u64 {
            return Err(FrameError::TooLarge {
                len: len.into(),
                max: self.max,
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
        Envelope::decode(body.freeze())
            .map(Some)
            .map_err(|_| FrameError::Invalid)
    }
}

impl Encoder<&Envelope> for FrameCodec {
    type Error = FrameError;

    fn encode(&mut self, item: &Envelope, dst: &mut BytesMut) -> Result<(), FrameError> {
        let len = item.encoded_len();
        if len > self.max {
            return Err(FrameError::TooLarge {
                len: len as u64,
                max: self.max,
            });
        }
        dst.reserve(PREFIX + len);
        // `len` fits: limits are far below u32::MAX.
        dst.put_u32(len as u32);
        item.encode(dst).map_err(|_| FrameError::Invalid)
    }
}

impl Encoder<Envelope> for FrameCodec {
    type Error = FrameError;

    fn encode(&mut self, item: Envelope, dst: &mut BytesMut) -> Result<(), FrameError> {
        self.encode(&item, dst)
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
            assert_eq!(err.code(), ErrorCode::TooLarge);
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
        // an unknown field: tag 15 length-delimited, 62 bytes of payload.
        buf.put_u8((15 << 3) | 2);
        buf.put_u8(62);
        buf.put_bytes(0, 62);
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
        assert_eq!(err.code(), ErrorCode::Invalid);
    }

    #[test]
    fn the_encoder_refuses_an_oversize_frame() {
        let mut codec = FrameCodec::with_limit(4);
        let mut buf = BytesMut::new();
        let big = Envelope {
            request_id: u32::MAX,
            last: true,
            body: Some(Body::Ping(Ping {})),
        };
        assert!(matches!(
            codec.encode(&big, &mut buf),
            Err(FrameError::TooLarge { .. })
        ));
        assert!(buf.is_empty());
    }
}
