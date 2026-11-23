//! `Envelope` decoding of arbitrary bytes, and what a receiver does next with
//! one: the server-only-body pre-check, the minor classification, `Debug`
//! (the redacting impls), error codes. Never panics; a decoded envelope
//! round-trips; a server-only body is always caught by the pre-check.
#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message;
use yapsta_proto::frame::carries_server_body;
use yapsta_proto::v1::{Envelope, envelope::Body};
use yapsta_proto::{WireCode, command_kind_name, minor_of};

fuzz_target!(|data: &[u8]| {
    let carries = carries_server_body(data);
    let Ok(env) = Envelope::decode(data) else {
        return;
    };
    let encoded = env.encode_to_vec();
    assert_eq!(encoded.len(), env.encoded_len());
    let again = Envelope::decode(encoded.as_slice()).expect("re-encoded envelope decodes");
    assert_eq!(again, env);
    let _ = format!("{env:?}");
    let Some(body) = &env.body else {
        return;
    };
    let minor = minor_of(body);
    assert!(
        (1..=yapsta_proto::MINOR_VERSION).contains(&minor),
        "minor {minor}"
    );
    match body {
        Body::Error(e) => {
            let _ = WireCode::of_error(e).is_normal_close();
            assert!(carries, "a server-only body the pre-check missed");
        }
        Body::Hello(_)
        | Body::Welcome(_)
        | Body::Event(_)
        | Body::Ephemeral(_)
        | Body::Ack(_)
        | Body::Resync(_)
        | Body::CommandResult(_)
        | Body::Response(_)
        | Body::Personal(_)
        | Body::PersonalSnapshot(_) => {
            assert!(carries, "a server-only body the pre-check missed");
        }
        Body::Command(c) => {
            if let Some(kind) = &c.kind {
                assert!(!command_kind_name(kind).is_empty());
            }
        }
        _ => {}
    }
});
