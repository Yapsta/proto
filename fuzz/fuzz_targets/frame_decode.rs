//! The frame decoder (§ 6.1) fed a byte stream in chunks, in each of the
//! codec's modes. Never panics; a frame is never bigger than the limit it was
//! decoded under; a server reading a client never gets a server-only body;
//! the buffer grows with the bytes received, not with a claimed length; every
//! decoded envelope re-encodes and decodes to itself.
#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use prost::Message;
use tokio_util::codec::{Decoder, Encoder};
use yapsta_proto::frame::{FrameCodec, FrameError, SERVER_ONLY_BODIES};
use yapsta_proto::v1::{Envelope, envelope::Body};
use yapsta_proto::{MAX_CONTROL_FRAME, MAX_RESTRICTED_FRAME};

/// The most `BytesMut` should hold past what was received: the decoder's
/// reserve step, doubled for `BytesMut`'s rounding, plus slack.
const SLACK: usize = 4 * 64 * 1024;

fn server_only(body: &Body) -> bool {
    let tag = match body {
        Body::Error(_) => 3,
        Body::Hello(_) => 4,
        Body::Welcome(_) => 6,
        Body::Event(_) => 7,
        Body::Ephemeral(_) => 8,
        Body::Ack(_) => 10,
        Body::Resync(_) => 13,
        Body::CommandResult(_) => 15,
        Body::Response(_) => 17,
        Body::Personal(_) => 19,
        Body::PersonalSnapshot(_) => 20,
        _ => return false,
    };
    debug_assert!(SERVER_ONLY_BODIES.contains(&tag));
    true
}

fuzz_target!(|data: &[u8]| {
    let [mode, chunk, rest @ ..] = data else {
        return;
    };
    let (mut codec, limit, from_client) = match mode % 5 {
        0 => (FrameCodec::control(), MAX_CONTROL_FRAME, false),
        1 => (FrameCodec::server_control(), MAX_CONTROL_FRAME, true),
        2 => {
            let mut c = FrameCodec::server_control();
            c.restrict(true);
            (c, MAX_RESTRICTED_FRAME, true)
        }
        3 => (FrameCodec::with_limit(64), 64, false),
        _ => (
            FrameCodec::request(),
            yapsta_proto::MAX_REQUEST_FRAME,
            false,
        ),
    };
    let chunk = usize::from(*chunk).max(1);
    let mut buf = BytesMut::new();
    let mut received = 0;
    let mut chunks = rest.chunks(chunk).peekable();
    while let Some(piece) = chunks.next() {
        buf.extend_from_slice(piece);
        received += piece.len();
        loop {
            let before = buf.len();
            let got = if chunks.peek().is_none() {
                codec.decode_eof(&mut buf)
            } else {
                codec.decode(&mut buf)
            };
            match got {
                Ok(Some(env)) => {
                    let consumed = before - buf.len();
                    assert!(
                        consumed >= 4 && consumed - 4 <= limit,
                        "frame over its limit"
                    );
                    if from_client {
                        assert!(
                            !env.body.as_ref().is_some_and(server_only),
                            "a server-only body got through"
                        );
                    }
                    let again = Envelope::decode(env.encode_to_vec().as_slice())
                        .expect("a decoded envelope re-encodes");
                    assert_eq!(again, env, "round trip");
                    let mut out = BytesMut::new();
                    let mut enc = FrameCodec::with_limit(usize::MAX);
                    enc.encode(&env, &mut out).expect("encodes");
                    let _ = format!("{env:?}");
                }
                Ok(None) => break,
                Err(FrameError::TooLarge { len, max }) => {
                    assert_eq!(max, limit);
                    assert!(len > max as u64);
                    return;
                }
                Err(FrameError::Invalid) => return,
                Err(FrameError::Io(e)) => panic!("the decoder made an I/O error: {e}"),
            }
        }
        assert!(
            buf.capacity() <= 2 * received + SLACK,
            "capacity {} for {received} bytes received",
            buf.capacity()
        );
    }
});
