//! The voice datagram header (docs/ARCHITECTURE.md § 6.4) byte by byte. Not
//! protobuf, so `wire_surface.rs` cannot pin it: these tests do.

use yapsta_proto::voice::{
    Codec, HEADER_LEN, Header, MAX_DATAGRAM, Reject, Route, VERSION, forwarded,
};

fn header() -> Header {
    Header {
        eot: true,
        dtx: false,
        codec: Codec::OpusMusic,
        route: Route::Whisper,
        seq: 0x0102,
        timestamp: 0x0304_0506,
        r#ref: 0x0708_090A,
    }
}

#[test]
fn the_header_layout_is_fixed_and_big_endian() {
    assert_eq!(HEADER_LEN, 16);
    assert_eq!(MAX_DATAGRAM, 1200);
    assert_eq!(VERSION, 1);
    assert_eq!(
        header().encode(),
        [
            0x11, // version 1 | EOT
            0x02, // opus-music
            0x01, // whisper
            0x00, // key_id
            0x01, 0x02, // seq
            0x03, 0x04, 0x05, 0x06, // timestamp
            0x07, 0x08, 0x09, 0x0A, // ref
            0x00, 0x00, // reserved
        ]
    );
    let dtx = Header {
        eot: false,
        dtx: true,
        codec: Codec::OpusVoice,
        route: Route::Channel,
        ..header()
    };
    assert_eq!(dtx.encode()[..3], [0x12, 0x01, 0x00]);
}

#[test]
fn a_datagram_parses_back_to_its_header_and_keeps_its_payload() {
    let payload = [0xF8, 0xFF, 0xFE];
    let datagram = header().datagram(&payload);
    assert_eq!(datagram.len(), HEADER_LEN + payload.len());
    assert_eq!(Header::parse(&datagram), Ok(header()));
    assert_eq!(&datagram[HEADER_LEN..], payload);
    // A bare header (no payload) is a datagram too.
    assert_eq!(Header::parse(&header().encode()), Ok(header()));
}

#[test]
fn the_unused_flag_bits_and_reserved_are_ignored_on_receipt() {
    let mut bytes = header().encode();
    bytes[0] |= 0x0C;
    bytes[14..16].copy_from_slice(&[0xAB, 0xCD]);
    assert_eq!(Header::parse(&bytes), Ok(header()));
}

#[test]
fn malformed_headers_are_rejected_with_a_reason() {
    let good = header().datagram(&[0; 32]);
    let with = |at: usize, value: u8| {
        let mut bytes = good.to_vec();
        bytes[at] = value;
        bytes
    };
    let cases: Vec<(&str, Vec<u8>, Reject, &str)> = vec![
        ("empty", vec![], Reject::TooShort, "too_short"),
        (
            "15 bytes",
            good[..15].to_vec(),
            Reject::TooShort,
            "too_short",
        ),
        (
            "1,201 bytes",
            vec![0x10, 1, 0, 0].into_iter().chain([0; 1197]).collect(),
            Reject::TooLong,
            "too_long",
        ),
        ("version 0", with(0, 0x01), Reject::Version, "version"),
        ("version 2", with(0, 0x21), Reject::Version, "version"),
        ("codec 0", with(1, 0), Reject::Codec, "codec"),
        ("codec 3", with(1, 3), Reject::Codec, "codec"),
        (
            "route 2 (direct, reserved)",
            with(2, 2),
            Reject::Route,
            "route",
        ),
        ("route 255", with(2, 255), Reject::Route, "route"),
        ("key_id 1", with(3, 1), Reject::KeyId, "key_id"),
    ];
    for (name, bytes, reject, reason) in cases {
        assert_eq!(Header::parse(&bytes), Err(reject), "{name}");
        assert_eq!(reject.reason(), reason, "{name}");
    }
    // The limits themselves are accepted.
    let largest = header().datagram(&[0; MAX_DATAGRAM - HEADER_LEN]);
    assert_eq!(largest.len(), MAX_DATAGRAM);
    assert!(Header::parse(&largest).is_ok());
}

#[test]
fn forwarding_rewrites_ref_zeroes_the_unused_bits_and_keeps_everything_else() {
    let mut received = header().datagram(b"opus-payload").to_vec();
    received[0] |= 0x0C;
    received[14..16].copy_from_slice(&[0xAB, 0xCD]);
    let out = forwarded(&received, 0xDEAD_BEEF).unwrap();
    assert_eq!(out.len(), received.len());
    assert_eq!(out[0], 0x11, "version and EOT kept, 0x4 and 0x8 cleared");
    assert_eq!(
        out[1..10],
        received[1..10],
        "codec, route, key_id, seq, timestamp"
    );
    assert_eq!(out[10..14], [0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(out[14..16], [0, 0]);
    assert_eq!(&out[HEADER_LEN..], b"opus-payload");
    assert_eq!(
        Header::parse(&out),
        Ok(Header {
            r#ref: 0xDEAD_BEEF,
            ..header()
        })
    );
    assert_eq!(forwarded(&received[..15], 1), None);
}

/// Parsing is total: no input panics or reads out of bounds. A fixed
/// xorshift stream stands in for a fuzzer, so the test is deterministic.
#[test]
fn parsing_never_panics_on_arbitrary_bytes() {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut accepted = 0;
    for round in 0..20_000 {
        let len = usize::try_from(next() % 1_300).unwrap();
        let mut bytes: Vec<u8> = (0..len).map(|_| next().to_le_bytes()[0]).collect();
        // Half the rounds start from a valid prefix, so the later checks run.
        if round % 2 == 0 && len >= HEADER_LEN {
            bytes[..4].copy_from_slice(&[0x10, 1, 0, 0]);
        }
        if let Ok(h) = Header::parse(&bytes) {
            accepted += 1;
            assert!((HEADER_LEN..=MAX_DATAGRAM).contains(&bytes.len()));
            let out = forwarded(&bytes, h.r#ref).unwrap();
            assert_eq!(Header::parse(&out), Ok(h));
        }
    }
    assert!(accepted > 1_000, "the valid-prefix rounds reach acceptance");
}
