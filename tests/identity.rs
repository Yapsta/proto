//! Identity (docs/ARCHITECTURE.md § 6.2): the known-answer vectors the client
//! and bot repos share, and every rejection the server relies on.

use prost::Message;
use yapsta_proto::identity::*;
use yapsta_proto::v1::{DeviceEntry, DeviceListBody, SignedDeviceList};

const VECTOR_SERVER_ID: &str = "a5jy5opmsxgrcsn22buvxzm5qi";
/// The server's clock in these tests: the example entries (1_807_776_000)
/// expire 90 days after it.
const NOW: ExpiryCap = ExpiryCap::At(1_800_000_000);
/// The order of the Ed25519 base point, little-endian.
const ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

fn hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}

fn unhex(hex: &str) -> Vec<u8> {
    data_encoding::HEXLOWER.decode(hex.as_bytes()).unwrap()
}

fn vector_seed() -> Seed {
    Seed::from_bytes(&std::array::from_fn(|i| i as u8))
}

fn server_id() -> ServerId {
    ServerId::parse(VECTOR_SERVER_ID).unwrap()
}

fn body(version: u64, devices: &[[u8; 32]]) -> DeviceListBody {
    DeviceListBody {
        version,
        devices: devices
            .iter()
            .map(|pub_| DeviceEntry {
                device_pub: pub_.to_vec(),
                expires_at: 1_807_776_000,
            })
            .collect(),
    }
}

fn device(n: u8) -> [u8; 32] {
    DeviceSecret::from_bytes(&[n; 32])
        .device_key(&server_id())
        .public()
        .to_bytes()
}

#[test]
fn the_known_answer_vectors() {
    // § 6.2: seed 00..1f on server a5jy5opmsxgrcsn22buvxzm5qi. Computed
    // independently (Python HKDF + RFC 8032 key generation).
    let sid = server_id();
    assert_eq!(
        hex(&vector_seed().account_key(&sid).public().to_bytes()),
        "120224b63eda1adfea27dcf54ec77523b9112693248cd393f76e196741d83455"
    );
    assert_eq!(
        hex(&DeviceSecret::from_bytes(vector_seed().as_bytes())
            .device_key(&sid)
            .public()
            .to_bytes()),
        "f79e984d99dac8855b8134d801aceafd48c884bba3f29e98d907af5142d92af4"
    );
    // server_id: the 28 ASCII bytes stand in for an SPKI.
    assert_eq!(
        ServerId::from_spki(b"yapsta server_id test vector").as_str(),
        VECTOR_SERVER_ID
    );
}

#[test]
fn server_ids_parse_strictly() {
    assert_eq!(server_id().to_string(), VECTOR_SERVER_ID);
    assert_eq!(server_id().as_bytes(), VECTOR_SERVER_ID.as_bytes());
    for bad in [
        "",
        "a5jy5opmsxgrcsn22buvxzm5q",   // 25
        "a5jy5opmsxgrcsn22buvxzm5qia", // 27
        "A5JY5OPMSXGRCSN22BUVXZM5QI",  // upper case
        "a5jy5opmsxgrcsn22buvxzm5q1",  // '1' is not base32
        "a5jy5opmsxgrcsn22buvxzm5q=",
    ] {
        assert_eq!(
            ServerId::parse(bad),
            Err(IdentityError::BadServerId),
            "{bad}"
        );
    }
}

#[test]
fn one_seed_gives_unlinkable_keys_per_instance() {
    let other = ServerId::from_spki(b"another instance");
    let seed = vector_seed();
    assert_ne!(
        seed.account_key(&server_id()).public(),
        seed.account_key(&other).public()
    );
    let device = DeviceSecret::from_bytes(&[7; 32]);
    assert_ne!(
        device.device_key(&server_id()).public(),
        device.device_key(&other).public()
    );
    // The salts separate account and device keys of the same 32 bytes.
    assert_ne!(
        seed.account_key(&server_id()).public(),
        DeviceSecret::from_bytes(seed.as_bytes())
            .device_key(&server_id())
            .public()
    );
}

#[test]
fn generated_secrets_are_fresh() {
    assert_ne!(
        Seed::generate().unwrap().as_bytes(),
        Seed::generate().unwrap().as_bytes()
    );
    assert_ne!(
        DeviceSecret::generate().unwrap().as_bytes(),
        DeviceSecret::generate().unwrap().as_bytes()
    );
}

#[test]
fn the_phrase_round_trips() {
    let seed = Seed::generate().unwrap();
    let phrase = seed.phrase();
    assert_eq!(phrase.split(' ').count(), 24);
    assert_eq!(
        Seed::from_phrase(&phrase).unwrap().as_bytes(),
        seed.as_bytes()
    );
    // Extra whitespace is fine; the words are what count.
    let spaced = format!("  {}\n", phrase.replace(' ', "   "));
    assert_eq!(
        Seed::from_phrase(&spaced).unwrap().as_bytes(),
        seed.as_bytes()
    );
    // The BIP-39 vector for 32 zero bytes: entropy, not the PBKDF2 seed.
    let zero = Seed::from_bytes(&[0; 32]);
    assert_eq!(
        zero.phrase().as_str(),
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon art"
    );
}

#[test]
fn bad_phrases_are_refused() {
    let phrase = vector_seed().phrase();
    let words: Vec<&str> = phrase.split(' ').collect();
    // A wrong checksum: the last word swapped for another valid word.
    let swapped = words[..23].join(" ")
        + if words[23] == "zoo" {
            " abandon"
        } else {
            " zoo"
        };
    // 12 words is valid BIP-39 but not a Yapsta phrase (16 bytes).
    let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    // NFKD would map these to ASCII words; they are refused, not normalized.
    let fullwidth = phrase.replacen('a', "\u{ff41}", 1);
    let nbsp = phrase.replacen(' ', "\u{a0}", 1);
    for bad in [
        swapped.as_str(),
        twelve,
        &fullwidth,
        &nbsp,
        &words[..23].join(" "),
        "",
        "not a phrase",
    ] {
        assert_eq!(
            Seed::from_phrase(bad).err(),
            Some(IdentityError::BadPhrase),
            "{bad}"
        );
    }
}

#[test]
fn a_signed_list_verifies_and_round_trips() {
    let account = vector_seed().account_key(&server_id());
    let sent = body(3, &[device(1), device(2)]);
    let list = account.sign_device_list(&sent).unwrap();
    assert_eq!(list.body, sent.encode_to_vec());
    assert_eq!(list.signature.len(), 64);
    assert_eq!(verify_device_list(&account.public(), &list, NOW), Ok(sent));
}

#[test]
fn a_tampered_or_foreign_list_is_refused() {
    let account = vector_seed().account_key(&server_id());
    let list = account.sign_device_list(&body(3, &[device(1)])).unwrap();

    // One flipped bit anywhere in the body or the signature.
    for i in 0..list.body.len() {
        let mut bad = list.clone();
        bad.body[i] ^= 1;
        assert_eq!(
            verify_device_list(&account.public(), &bad, NOW),
            Err(IdentityError::BadSignature),
            "body byte {i}"
        );
    }
    let mut bad = list.clone();
    bad.signature[10] ^= 1;
    assert_eq!(
        verify_device_list(&account.public(), &bad, NOW),
        Err(IdentityError::BadSignature)
    );
    // Truncated or missing signature.
    for len in [0, 63] {
        let mut bad = list.clone();
        bad.signature.truncate(len);
        assert_eq!(
            verify_device_list(&account.public(), &bad, NOW),
            Err(IdentityError::BadSignature)
        );
    }
    // Signed by another account.
    let other = Seed::from_bytes(&[9; 32]).account_key(&server_id());
    assert_eq!(
        verify_device_list(&other.public(), &list, NOW),
        Err(IdentityError::BadSignature)
    );
    // A valid signature over the body without the domain prefix.
    let unprefixed = sign_with_vector_account(&list.body);
    let bad = SignedDeviceList {
        body: list.body.clone(),
        signature: unprefixed,
    };
    assert_eq!(
        verify_device_list(&account.public(), &bad, NOW),
        Err(IdentityError::BadSignature)
    );
}

/// § 6.2's derivation by hand, on the hkdf crate: an independent check of the
/// module's own HKDF, and a key a test can sign anything with.
fn hand_derived(salt: &[u8], secret: &[u8; 32]) -> ed25519_dalek::SigningKey {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), secret);
    let mut okm = [0; 32];
    hk.expand(VECTOR_SERVER_ID.as_bytes(), &mut okm).unwrap();
    ed25519_dalek::SigningKey::from_bytes(&okm)
}

fn vector_account_signing_key() -> ed25519_dalek::SigningKey {
    hand_derived(b"yapsta/account/v1", vector_seed().as_bytes())
}

/// The vector account key's signature over any `message`, so a test can sign
/// what the API would refuse to.
fn sign_with_vector_account(message: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer;
    vector_account_signing_key()
        .sign(message)
        .to_bytes()
        .to_vec()
}

#[test]
fn a_non_canonical_signature_is_refused() {
    let account = vector_seed().account_key(&server_id());
    let mut list = account.sign_device_list(&body(1, &[device(1)])).unwrap();
    // S + L: the same scalar mod L, so a lax verifier would accept it.
    let mut carry = 0u16;
    for (s, l) in list.signature[32..].iter_mut().zip(ORDER) {
        let sum = u16::from(*s) + u16::from(l) + carry;
        *s = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    assert_eq!(
        verify_device_list(&account.public(), &list, NOW),
        Err(IdentityError::BadSignature)
    );
}

#[test]
fn weak_and_malformed_keys_are_refused() {
    // Small-order points: the identity, a point of order 2, order 4, and
    // -identity's non-canonical sign bit.
    let mut weak = vec![
        unhex("0100000000000000000000000000000000000000000000000000000000000000"),
        unhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        unhex("0000000000000000000000000000000000000000000000000000000000000000"),
        unhex("0100000000000000000000000000000000000000000000000000000000000080"),
    ];
    // y = p + 3: decodes to the same point as y = 3, but not canonically.
    let non_canonical = unhex("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    let canonical = unhex("0300000000000000000000000000000000000000000000000000000000000000");
    assert!(PublicKey::from_slice(&canonical).is_ok());
    weak.push(non_canonical);
    weak.extend([vec![], vec![1; 31], vec![1; 33]]);
    for key in &weak {
        assert_eq!(
            PublicKey::from_slice(key),
            Err(IdentityError::BadKey),
            "{}",
            hex(key)
        );
    }

    // A list may not list one either.
    let account = vector_seed().account_key(&server_id());
    let weak_device: [u8; 32] = weak[0].clone().try_into().unwrap();
    let list = account
        .sign_device_list(&body(1, &[device(1), weak_device]))
        .unwrap();
    assert_eq!(
        verify_device_list(&account.public(), &list, NOW),
        Err(IdentityError::BadKey)
    );
}

#[test]
fn list_limits() {
    let account = vector_seed().account_key(&server_id());
    let many: Vec<[u8; 32]> = (0..=64).map(device).collect();
    for bad in [
        body(0, &[device(1)]),
        body(1, &many),
        body(1, &[device(1), device(2), device(1)]),
    ] {
        // The signer refuses it...
        assert_eq!(
            account.sign_device_list(&bad).err(),
            Some(IdentityError::ListLimit)
        );
        // ...and so does the verifier, when another client signed it anyway.
        let list = sign_raw(&bad.encode_to_vec());
        assert_eq!(
            verify_device_list(&account.public(), &list, NOW),
            Err(IdentityError::ListLimit)
        );
    }
    // 64 entries is the limit, inclusive; an empty list is allowed.
    let full = body(1, &many[..64]);
    let list = account.sign_device_list(&full).unwrap();
    assert_eq!(verify_device_list(&account.public(), &list, NOW), Ok(full));
    let empty = body(1, &[]);
    let list = account.sign_device_list(&empty).unwrap();
    assert_eq!(verify_device_list(&account.public(), &list, NOW), Ok(empty));
}

#[test]
fn an_oversized_body_is_refused_before_it_is_verified() {
    let account = vector_seed().account_key(&server_id());
    // Correctly signed, so only the size can refuse it.
    let at_limit = sign_raw(&vec![0; MAX_DEVICE_LIST_BODY]);
    assert_ne!(
        verify_device_list(&account.public(), &at_limit, NOW),
        Err(IdentityError::ListLimit)
    );
    let over = sign_raw(&vec![0; MAX_DEVICE_LIST_BODY + 1]);
    assert_eq!(
        verify_device_list(&account.public(), &over, NOW),
        Err(IdentityError::ListLimit)
    );
}

#[test]
fn a_body_that_does_not_decode_is_refused_after_the_signature() {
    let list = sign_raw(&[0xff, 0xff, 0xff]);
    let account = vector_seed().account_key(&server_id());
    assert_eq!(
        verify_device_list(&account.public(), &list, NOW),
        Err(IdentityError::BadBody)
    );
}

/// Signs any bytes as a device list with the vector account key, bypassing
/// the signer's checks: what a misbehaving client could send.
fn sign_raw(body: &[u8]) -> SignedDeviceList {
    let mut message = b"yapsta/device-list/v1\0".to_vec();
    message.extend_from_slice(body);
    SignedDeviceList {
        body: body.to_vec(),
        signature: sign_with_vector_account(&message),
    }
}

#[test]
fn the_expiry_cap() {
    let now = 1_800_000_000;
    let cap = now + MAX_CERT_LIFETIME_SECS + CLOCK_SKEW_SECS;
    let account = vector_seed().account_key(&server_id());
    let at = |expires_at| {
        account
            .sign_device_list(&DeviceListBody {
                version: 1,
                devices: vec![
                    DeviceEntry {
                        device_pub: device(1).to_vec(),
                        expires_at: 0, // long expired: allowed in the list
                    },
                    DeviceEntry {
                        device_pub: device(2).to_vec(),
                        expires_at,
                    },
                ],
            })
            .unwrap()
    };
    let verify = |list, cap| verify_device_list(&account.public(), &list, cap).map(|_| ());
    assert_eq!(verify(at(cap), ExpiryCap::At(now)), Ok(()));
    assert_eq!(
        verify(at(cap + 1), ExpiryCap::At(now)),
        Err(IdentityError::ExpiryTooFar)
    );
    // A client reading `Welcome` does not check it; the cap never overflows.
    assert_eq!(verify(at(u64::MAX), ExpiryCap::Unchecked), Ok(()));
    assert_eq!(verify(at(u64::MAX), ExpiryCap::At(u64::MAX)), Ok(()));
}

#[test]
fn the_auth_transcript() {
    let sid = server_id();
    let account = vector_seed().account_key(&sid).public();
    let device_key = DeviceSecret::from_bytes(&[1; 32]).device_key(&sid);
    let device_pub = device_key.public();
    let transcript = AuthTranscript {
        server_id: &sid,
        challenge: &[0xc1; 32],
        exporter: &[0xe2; 32],
        account_pub: &account,
        device_pub: &device_pub,
    };
    // The layout of § 6.2's table, field by field.
    let bytes = transcript.to_bytes();
    assert_eq!(bytes.len(), 15 + 26 + 4 * 32);
    assert_eq!(&bytes[..15], b"yapsta/auth/v1\0");
    assert_eq!(&bytes[15..41], VECTOR_SERVER_ID.as_bytes());
    assert_eq!(&bytes[41..73], &[0xc1; 32]);
    assert_eq!(&bytes[73..105], &[0xe2; 32]);
    assert_eq!(&bytes[105..137], &account.to_bytes());
    assert_eq!(&bytes[137..], &device_pub.to_bytes());

    let signature = device_key.sign_auth(&transcript).unwrap();
    assert_eq!(transcript.verify(&signature), Ok(()));

    // Any other connection, server or account: the signature no longer fits.
    let other_sid = ServerId::from_spki(b"elsewhere");
    let other_account = Seed::from_bytes(&[3; 32]).account_key(&sid).public();
    for changed in [
        AuthTranscript {
            challenge: &[0xc2; 32],
            ..transcript
        },
        AuthTranscript {
            exporter: &[0xe3; 32],
            ..transcript
        },
        AuthTranscript {
            server_id: &other_sid,
            ..transcript
        },
        AuthTranscript {
            account_pub: &other_account,
            ..transcript
        },
    ] {
        assert_eq!(changed.verify(&signature), Err(IdentityError::BadSignature));
    }
    assert_eq!(
        transcript.verify(&signature[..63]),
        Err(IdentityError::BadSignature)
    );

    // A device key never signs a transcript naming another key.
    let other_device = DeviceSecret::from_bytes(&[2; 32]).device_key(&sid);
    assert_eq!(
        other_device.sign_auth(&transcript),
        Err(IdentityError::BadKey)
    );

    // The connection binding stays out of Debug.
    let shown = format!("{transcript:?}");
    assert!(!shown.contains("193") && !shown.contains("c1c1"), "{shown}"); // 0xc1
    assert!(!shown.contains("226") && !shown.contains("e2e2"), "{shown}"); // 0xe2
    assert!(shown.contains(VECTOR_SERVER_ID), "{shown}");
}

/// A signature with a small-order R: S = k·a, so S·B = k·A = R + k·A. Plain
/// `verify` accepts it; `verify_strict` must not (§ 6.2).
fn forge_small_order_r(key: &ed25519_dalek::SigningKey, message: &[u8]) -> Vec<u8> {
    use curve25519_dalek::Scalar;
    use sha2::{Digest, Sha512};
    let r = unhex("0100000000000000000000000000000000000000000000000000000000000000");
    let mut h = Sha512::new();
    h.update(&r);
    h.update(key.verifying_key().as_bytes());
    h.update(message);
    let k = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
    let s = k * key.to_scalar();
    let signature = [r.as_slice(), s.as_bytes()].concat();
    // Guard against the test going hollow: a lax verifier takes it.
    let lax = ed25519_dalek::Signature::from_slice(&signature).unwrap();
    assert!(ed25519_dalek::Verifier::verify(&key.verifying_key(), message, &lax).is_ok());
    signature
}

#[test]
fn a_small_order_r_is_refused() {
    let account = vector_seed().account_key(&server_id());
    let list = account.sign_device_list(&body(1, &[device(1)])).unwrap();
    let mut message = b"yapsta/device-list/v1\0".to_vec();
    message.extend_from_slice(&list.body);
    let forged = SignedDeviceList {
        signature: forge_small_order_r(&vector_account_signing_key(), &message),
        ..list
    };
    assert_eq!(
        verify_device_list(&account.public(), &forged, NOW),
        Err(IdentityError::BadSignature)
    );

    // The same for the Auth transcript.
    let sid = server_id();
    let secret = DeviceSecret::from_bytes(&[1; 32]);
    let device_pub = secret.device_key(&sid).public();
    let account_pub = account.public();
    let transcript = AuthTranscript {
        server_id: &sid,
        challenge: &[0xc1; 32],
        exporter: &[0xe2; 32],
        account_pub: &account_pub,
        device_pub: &device_pub,
    };
    let device_signing = hand_derived(b"yapsta/device/v1", secret.as_bytes());
    let forged = forge_small_order_r(&device_signing, &transcript.to_bytes());
    assert_eq!(transcript.verify(&forged), Err(IdentityError::BadSignature));
}

#[test]
fn debug_never_shows_secrets() {
    let seed = vector_seed();
    let secret = DeviceSecret::from_bytes(&[0xab; 32]);
    let shown = format!(
        "{seed:?} {secret:?} {:?} {:?}",
        seed.account_key(&server_id()),
        secret.device_key(&server_id())
    );
    assert!(!shown.contains("171"), "{shown}"); // 0xab
    assert!(!shown.contains("abab"), "{shown}");
    assert!(!shown.contains("[0, 1, 2"), "{shown}");
    assert!(!shown.contains("000102"), "{shown}");
    // Derived secrets: the HKDF output must not show either.
    assert!(!shown.contains("fe86c8f5"), "{shown}");
    assert!(shown.contains("<redacted>"), "{shown}");
    // Public keys do show, as hex.
    assert!(shown.contains("120224b63eda1adf"), "{shown}");
}
