//! The voice datagram header (§ 6.4): every datagram a QUIC peer sends is
//! parsed by it. Never panics; a parsed header re-encodes to the bytes it
//! keeps; the forwarded copy keeps the length and what § 6.4 says it keeps.
#![no_main]

use libfuzzer_sys::fuzz_target;
use yapsta_proto::voice::{HEADER_LEN, Header, forwarded};

fuzz_target!(|data: &[u8]| {
    let Ok(header) = Header::parse(data) else {
        return;
    };
    let encoded = header.encode();
    assert_eq!(Header::parse(&encoded), Ok(header));
    assert_eq!(encoded[4..14], data[4..14]);
    let out = forwarded(data, 7).expect("a parsed datagram has a header");
    assert_eq!(out.len(), data.len());
    assert_eq!(out[HEADER_LEN..], data[HEADER_LEN..]);
    let again = Header::parse(&out).expect("a forwarded datagram parses");
    assert_eq!(again.r#ref, 7);
    assert_eq!((again.seq, again.timestamp), (header.seq, header.timestamp));
    let _ = format!("{header:?}");
});
