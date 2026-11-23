//! The identity parsers a peer reaches (§ 6.2, § 6.15): public keys, signed
//! device lists, server ids, recovery phrases and bot seeds. Never panics;
//! what parses round-trips.
#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message;
use yapsta_proto::identity::{
    AuthTranscript, BotSeed, ExpiryCap, MAX_DEVICES, PublicKey, Seed, ServerId, verify_device_list,
};
use yapsta_proto::v1::SignedDeviceList;

fuzz_target!(|data: &[u8]| {
    let [selector, rest @ ..] = data else {
        return;
    };
    match selector % 5 {
        0 => {
            if let Ok(key) = PublicKey::from_slice(rest) {
                assert_eq!(&key.to_bytes()[..], rest, "keys are their canonical bytes");
            }
        }
        1 => {
            // An account key, then a `SignedDeviceList` as the wire carries it.
            let Some((key, list)) = rest.split_first_chunk::<32>() else {
                return;
            };
            let Ok(account) = PublicKey::from_slice(key) else {
                return;
            };
            let Ok(list) = SignedDeviceList::decode(list) else {
                return;
            };
            for cap in [
                ExpiryCap::Unchecked,
                ExpiryCap::At(u64::MAX),
                ExpiryCap::At(0),
            ] {
                if let Ok(body) = verify_device_list(&account, &list, cap) {
                    assert!(body.version > 0 && body.devices.len() <= MAX_DEVICES);
                }
            }
        }
        2 => {
            let Ok(text) = std::str::from_utf8(rest) else {
                return;
            };
            if let Ok(id) = ServerId::parse(text) {
                assert_eq!(id.as_str(), text);
            }
            if let Ok(seed) = Seed::from_phrase(text) {
                let again = Seed::from_phrase(&seed.phrase()).expect("its own phrase parses");
                assert_eq!(again.as_bytes(), seed.as_bytes());
            }
            if let Ok(seed) = BotSeed::from_text(text) {
                let again = BotSeed::from_text(&seed.text()).expect("its own text parses");
                assert_eq!(seed.text().as_str(), again.text().as_str());
                assert_eq!(seed.text().as_str(), text.trim().to_ascii_lowercase());
            }
        }
        3 => {
            // An `Auth` transcript's verification with arbitrary parts.
            let Some((parts, signature)) = rest.split_first_chunk::<128>() else {
                return;
            };
            let id = ServerId::from_spki(&parts[..32]);
            let challenge: &[u8; 32] = parts[..32].try_into().unwrap();
            let exporter: &[u8; 32] = parts[32..64].try_into().unwrap();
            let (Ok(account_pub), Ok(device_pub)) = (
                PublicKey::from_slice(&parts[64..96]),
                PublicKey::from_slice(&parts[96..128]),
            ) else {
                return;
            };
            let _ = AuthTranscript {
                server_id: &id,
                challenge,
                exporter,
                account_pub: &account_pub,
                device_pub: &device_pub,
            }
            .verify(signature);
        }
        _ => {
            let id = ServerId::from_spki(rest);
            assert_eq!(ServerId::parse(id.as_str()), Ok(id));
        }
    }
});
