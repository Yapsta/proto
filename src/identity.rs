//! Identity (docs/PROTOCOL.md § 6.2): the seed and its recovery phrase,
//! the per-instance account and device keys, device lists and the `Auth`
//! transcript; from M8 a bot's seed, key and `Auth` transcript (§ 6.15).
//! Clients and bots derive and sign with it; the server verifies with it.
//!
//! - Secrets (seed, device secret, derived keys) are zeroized on drop and never
//!   shown by `Debug`.
//! - Every signature is checked with `verify_strict`, and keys must be 32
//!   canonical bytes of a point that is not of small order.
//! - Nothing signed is a re-encoded protobuf: a device list is verified over
//!   the body bytes as received, and the body is decoded only after that.

use std::collections::HashSet;
use std::fmt::{self, Write};

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use prost::Message;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::v1::{DeviceListBody, SignedDeviceList};

const ACCOUNT_SALT: &[u8] = b"yapsta/account/v1";
const DEVICE_SALT: &[u8] = b"yapsta/device/v1";
const DEVICE_LIST_PREFIX: &[u8] = b"yapsta/device-list/v1\0";
const AUTH_PREFIX: &[u8] = b"yapsta/auth/v1\0";
const BOT_SALT: &[u8] = b"yapsta/bot/v1";
const BOT_AUTH_PREFIX: &[u8] = b"yapsta/bot-auth/v1\0";
/// A bot seed's text form: 32 bytes as unpadded base32 (§ 6.15).
pub const BOT_SEED_TEXT_LEN: usize = 52;
const SERVER_ID_LEN: usize = 26;

/// The TLS exporter `Auth` is bound to (§ 6.2): this label, an **empty**
/// context (`b""` with quinn, `Some(b"")` with rustls), [`EXPORTER_LEN`]
/// bytes. Stable API (§ 6.7).
pub const EXPORTER_LABEL: &[u8] = b"yapsta-auth";
pub const EXPORTER_LEN: usize = 32;
const PHRASE_WORDS: usize = 24;
/// The longest English BIP-39 word.
const LONGEST_WORD: usize = 8;

/// The most entries a device list may hold.
pub const MAX_DEVICES: usize = 64;
/// The largest device-list body accepted, checked before it is hashed or
/// decoded. A full list of 64 entries encodes to about 3 KiB; the rest is room
/// for fields a later version adds (§ 6.7).
pub const MAX_DEVICE_LIST_BODY: usize = 16 * 1024;
/// How far ahead a device certificate may expire: 90 days.
pub const MAX_CERT_LIFETIME_SECS: u64 = 90 * 24 * 60 * 60;
/// Clock skew allowed on top of [`MAX_CERT_LIFETIME_SECS`].
pub const CLOCK_SKEW_SECS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    #[error("the OS random number generator failed")]
    Rng,
    #[error("not a 24-word English recovery phrase")]
    BadPhrase,
    #[error("not a server id")]
    BadServerId,
    /// Wrong length, not a canonical point encoding, or a small-order point.
    #[error("not a usable Ed25519 public key")]
    BadKey,
    #[error("the signature does not verify")]
    BadSignature,
    #[error("the device-list body does not decode")]
    BadBody,
    /// Version 0, more than [`MAX_DEVICES`] entries, or a repeated device.
    #[error("the device list breaks a limit")]
    ListLimit,
    #[error("a device certificate expires too far ahead")]
    ExpiryTooFar,
    #[error("not a bot seed")]
    BadBotSeed,
}

/// An instance's id: the first 26 characters of the lowercase, unpadded
/// base32 of SHA-256 over its certificate's SubjectPublicKeyInfo.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServerId([u8; SERVER_ID_LEN]);

impl ServerId {
    /// Computes the id from the DER bytes of a SubjectPublicKeyInfo. Clients
    /// use the pinned SPKI, never the copy in `Hello`.
    pub fn from_spki(spki_der: &[u8]) -> Self {
        let encoded = BASE32_NOPAD.encode(&Sha256::digest(spki_der));
        let mut id = [0; SERVER_ID_LEN];
        for (out, c) in id.iter_mut().zip(encoded.bytes()) {
            *out = c.to_ascii_lowercase();
        }
        Self(id)
    }

    /// Accepts exactly 26 characters of the lowercase base32 alphabet.
    pub fn parse(s: &str) -> Result<Self, IdentityError> {
        let id: [u8; SERVER_ID_LEN] = s
            .as_bytes()
            .try_into()
            .map_err(|_| IdentityError::BadServerId)?;
        if id.iter().all(|c| matches!(c, b'a'..=b'z' | b'2'..=b'7')) {
            Ok(Self(id))
        } else {
            Err(IdentityError::BadServerId)
        }
    }

    /// The 26 ASCII bytes: the HKDF `info` and part of the `Auth` transcript.
    pub fn as_bytes(&self) -> &[u8; SERVER_ID_LEN] {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        // Only ever built from ASCII (`from_spki`, `parse`).
        std::str::from_utf8(&self.0).unwrap_or_default()
    }
}

impl fmt::Display for ServerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for ServerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServerId({})", self.as_str())
    }
}

/// A person's identity seed: 32 random bytes, shown once as a 24-word phrase.
pub struct Seed(Zeroizing<[u8; 32]>);

impl Seed {
    /// A fresh seed from the OS RNG.
    pub fn generate() -> Result<Self, IdentityError> {
        random().map(Self)
    }

    /// A seed read back from the client's own storage.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(Zeroizing::new(*bytes))
    }

    /// The bytes, for the client's own storage only.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Restores a seed from its recovery phrase: the BIP-39 English mnemonic
    /// of the 32 bytes as entropy (never the BIP-39 PBKDF2 "seed"). The
    /// English words are ASCII, so other input is refused rather than
    /// normalized into a copy that could not be zeroized.
    pub fn from_phrase(phrase: &str) -> Result<Self, IdentityError> {
        if !phrase.is_ascii() {
            return Err(IdentityError::BadPhrase);
        }
        let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, phrase)
            .map_err(|_| IdentityError::BadPhrase)?;
        if mnemonic.word_count() != PHRASE_WORDS {
            return Err(IdentityError::BadPhrase);
        }
        let (entropy, len) = mnemonic.to_entropy_array();
        let entropy = Zeroizing::new(entropy);
        let mut seed = Zeroizing::new([0; 32]);
        seed.copy_from_slice(&entropy[..len]);
        Ok(Self(seed))
    }

    /// The 24-word recovery phrase.
    pub fn phrase(&self) -> Zeroizing<String> {
        let mnemonic = bip39::Mnemonic::from_entropy_in(bip39::Language::English, &self.0[..])
            .expect("32 bytes is a valid BIP-39 entropy length");
        // Sized up front: growing would free partial copies unzeroized.
        let mut phrase = Zeroizing::new(String::with_capacity(PHRASE_WORDS * (LONGEST_WORD + 1)));
        write!(phrase, "{mnemonic}").expect("writing to a String never fails");
        phrase
    }

    /// This seed's account key on one instance.
    pub fn account_key(&self, server_id: &ServerId) -> AccountKey {
        AccountKey(derive(&self.0, ACCOUNT_SALT, server_id))
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(<redacted>)")
    }
}

/// A device's own secret: 32 random bytes that never leave the device.
pub struct DeviceSecret(Zeroizing<[u8; 32]>);

impl DeviceSecret {
    pub fn generate() -> Result<Self, IdentityError> {
        random().map(Self)
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(Zeroizing::new(*bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// This device's key on one instance.
    pub fn device_key(&self, server_id: &ServerId) -> DeviceKey {
        DeviceKey(derive(&self.0, DEVICE_SALT, server_id))
    }
}

impl fmt::Debug for DeviceSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceSecret(<redacted>)")
    }
}

/// An account key on one instance; it signs device lists.
pub struct AccountKey(SigningKey);

impl AccountKey {
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// Encodes `body` once and signs those bytes. Fails on a list that breaks
    /// a limit, which no instance would accept.
    pub fn sign_device_list(
        &self,
        body: &DeviceListBody,
    ) -> Result<SignedDeviceList, IdentityError> {
        check_limits(body)?;
        let body = body.encode_to_vec();
        let signature = self.0.sign(&[DEVICE_LIST_PREFIX, &body].concat());
        Ok(SignedDeviceList {
            body,
            signature: signature.to_bytes().to_vec(),
        })
    }
}

impl fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AccountKey").field(&self.public()).finish()
    }
}

/// A device key on one instance; it signs the `Auth` transcript.
pub struct DeviceKey(SigningKey);

impl DeviceKey {
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// Signs `transcript`. Refuses one that names another key as its
    /// `device_pub`, which no server would accept.
    pub fn sign_auth(&self, transcript: &AuthTranscript<'_>) -> Result<[u8; 64], IdentityError> {
        if transcript.device_pub != &self.public() {
            return Err(IdentityError::BadKey);
        }
        Ok(self.0.sign(&transcript.to_bytes()).to_bytes())
    }
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DeviceKey").field(&self.public()).finish()
    }
}

/// A bot's seed (§ 6.15): 32 random bytes the server shows once, as
/// [`BOT_SEED_TEXT_LEN`] lowercase base32 characters, and never keeps.
pub struct BotSeed(Zeroizing<[u8; 32]>);

impl BotSeed {
    /// A fresh seed from the OS RNG.
    pub fn generate() -> Result<Self, IdentityError> {
        random().map(Self)
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(Zeroizing::new(*bytes))
    }

    /// Reads the text form. Surrounding whitespace is ignored and either case
    /// is accepted; anything else that is not 52 base32 characters for 32
    /// bytes is refused. Works in zeroizing buffers only.
    pub fn from_text(text: &str) -> Result<Self, IdentityError> {
        let text = text.trim();
        if text.len() != BOT_SEED_TEXT_LEN || !text.is_ascii() {
            return Err(IdentityError::BadBotSeed);
        }
        let mut upper = Zeroizing::new([0u8; BOT_SEED_TEXT_LEN]);
        upper.copy_from_slice(text.as_bytes());
        upper.make_ascii_uppercase();
        let mut seed = Zeroizing::new([0u8; 32]);
        BASE32_NOPAD
            .decode_mut(&upper[..], &mut seed[..])
            .map_err(|_| IdentityError::BadBotSeed)?;
        // Base32 of 32 bytes leaves 4 spare bits in the last character: only
        // the canonical encoding (spare bits zero) is a seed. `BASE32_NOPAD`
        // checks trailing bits, so `decode_mut` refuses any other.
        Ok(Self(seed))
    }

    /// The text form, lowercase: what `create_bot` returns once.
    pub fn text(&self) -> Zeroizing<String> {
        // `encode` allocates exactly once, so no unzeroized copy is left.
        let mut text = Zeroizing::new(BASE32_NOPAD.encode(&self.0[..]));
        text.make_ascii_lowercase();
        text
    }

    /// The bot's key on one instance: `Ed25519(HKDF-SHA256(seed,
    /// salt="yapsta/bot/v1", info=server_id))`, derived as the account key.
    pub fn bot_key(&self, server_id: &ServerId) -> BotKey {
        BotKey(derive(&self.0, BOT_SALT, server_id))
    }
}

impl fmt::Debug for BotSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BotSeed(<redacted>)")
    }
}

/// A bot's key on one instance; it signs the bot `Auth` transcript.
pub struct BotKey(SigningKey);

impl BotKey {
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// Signs `transcript`. Refuses one that names another key as its
    /// `bot_pub`, which no server would accept.
    pub fn sign_auth(&self, transcript: &BotAuthTranscript<'_>) -> Result<[u8; 64], IdentityError> {
        if transcript.bot_pub != &self.public() {
            return Err(IdentityError::BadKey);
        }
        Ok(self.0.sign(&transcript.to_bytes()).to_bytes())
    }
}

impl fmt::Debug for BotKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BotKey").field(&self.public()).finish()
    }
}

/// An Ed25519 public key that is safe to verify with: 32 canonical bytes of a
/// point that is not of small order. Equal keys have equal bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, IdentityError> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| IdentityError::BadKey)?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| IdentityError::BadKey)?;
        // Decompression accepts a few non-canonical encodings; keys are
        // compared by their bytes, so only the canonical one is a key.
        if key.is_weak() || key.to_edwards().compress().to_bytes() != bytes {
            return Err(IdentityError::BadKey);
        }
        Ok(Self(key))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// `verify_strict` of a 64-byte `signature` over `message`.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), IdentityError> {
        let signature =
            Signature::from_slice(signature).map_err(|_| IdentityError::BadSignature)?;
        self.0
            .verify_strict(message, &signature)
            .map_err(|_| IdentityError::BadSignature)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PublicKey({})",
            data_encoding::HEXLOWER.encode(self.0.as_bytes())
        )
    }
}

/// Whether [`verify_device_list`] checks the 90-day cap. The crate keeps no
/// clock, so the caller says which: the server always passes its own `now`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryCap {
    /// Reject any entry that expires more than 90 days (plus clock skew)
    /// after this time, in unix seconds. Entries already expired are allowed.
    At(u64),
    /// No cap: for a client reading the list in `Welcome`.
    Unchecked,
}

/// Verifies `list` against the account key over the body bytes as received,
/// then decodes the body and checks its limits, its keys and the expiry cap.
pub fn verify_device_list(
    account: &PublicKey,
    list: &SignedDeviceList,
    cap: ExpiryCap,
) -> Result<DeviceListBody, IdentityError> {
    if list.body.len() > MAX_DEVICE_LIST_BODY {
        return Err(IdentityError::ListLimit);
    }
    account.verify(&[DEVICE_LIST_PREFIX, &list.body].concat(), &list.signature)?;
    let body = DeviceListBody::decode(list.body.as_slice()).map_err(|_| IdentityError::BadBody)?;
    check_limits(&body)?;
    for entry in &body.devices {
        PublicKey::from_slice(&entry.device_pub)?;
    }
    if let ExpiryCap::At(now) = cap {
        let cap = now.saturating_add(MAX_CERT_LIFETIME_SECS + CLOCK_SKEW_SECS);
        if body.devices.iter().any(|entry| entry.expires_at > cap) {
            return Err(IdentityError::ExpiryTooFar);
        }
    }
    Ok(body)
}

fn check_limits(body: &DeviceListBody) -> Result<(), IdentityError> {
    if body.version == 0 || body.devices.len() > MAX_DEVICES {
        return Err(IdentityError::ListLimit);
    }
    let mut seen = HashSet::with_capacity(body.devices.len());
    if !body
        .devices
        .iter()
        .all(|entry| seen.insert(&entry.device_pub))
    {
        return Err(IdentityError::ListLimit);
    }
    Ok(())
}

/// What a device signs in `Auth`: every field has a fixed length, so the
/// concatenation after the domain prefix is unambiguous.
#[derive(Clone, Copy)]
pub struct AuthTranscript<'a> {
    /// Recomputed from the pinned SPKI by the client.
    pub server_id: &'a ServerId,
    /// `Hello.challenge`.
    pub challenge: &'a [u8; 32],
    /// The TLS exporter: [`EXPORTER_LABEL`], empty context, [`EXPORTER_LEN`] bytes.
    pub exporter: &'a [u8; EXPORTER_LEN],
    pub account_pub: &'a PublicKey,
    pub device_pub: &'a PublicKey,
}

impl AuthTranscript<'_> {
    /// The signed bytes: `yapsta/auth/v1 0x00 ‖ server_id ‖ challenge ‖
    /// exporter ‖ account_pub ‖ device_pub`.
    pub fn to_bytes(&self) -> Vec<u8> {
        [
            AUTH_PREFIX,
            self.server_id.as_bytes(),
            self.challenge,
            self.exporter,
            self.account_pub.0.as_bytes(),
            self.device_pub.0.as_bytes(),
        ]
        .concat()
    }

    /// `verify_strict` of the device key's `signature` over this transcript.
    pub fn verify(&self, signature: &[u8]) -> Result<(), IdentityError> {
        self.device_pub.verify(&self.to_bytes(), signature)
    }
}

/// The challenge and the exporter are this connection's binding: kept out of
/// logs, like everything a stray `{:?}` could reach.
impl fmt::Debug for AuthTranscript<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            server_id,
            challenge: _,
            exporter: _,
            account_pub,
            device_pub,
        } = self;
        f.debug_struct("AuthTranscript")
            .field("server_id", server_id)
            .field("challenge", &"<redacted>")
            .field("exporter", &"<redacted>")
            .field("account_pub", account_pub)
            .field("device_pub", device_pub)
            .finish()
    }
}

/// What a bot signs in `Auth` (§ 6.15): fixed-length fields after their own
/// domain prefix, so it can never be taken for a device's transcript.
#[derive(Clone, Copy)]
pub struct BotAuthTranscript<'a> {
    /// Recomputed from the pinned SPKI by the bot.
    pub server_id: &'a ServerId,
    /// `Hello.challenge`.
    pub challenge: &'a [u8; 32],
    /// The TLS exporter, exactly as for devices.
    pub exporter: &'a [u8; EXPORTER_LEN],
    pub bot_pub: &'a PublicKey,
}

impl BotAuthTranscript<'_> {
    /// The signed bytes: `yapsta/bot-auth/v1 0x00 ‖ server_id ‖ challenge ‖
    /// exporter ‖ bot_pub`.
    pub fn to_bytes(&self) -> Vec<u8> {
        [
            BOT_AUTH_PREFIX,
            self.server_id.as_bytes(),
            self.challenge,
            self.exporter,
            self.bot_pub.0.as_bytes(),
        ]
        .concat()
    }

    /// `verify_strict` of the bot key's `signature` over this transcript.
    pub fn verify(&self, signature: &[u8]) -> Result<(), IdentityError> {
        self.bot_pub.verify(&self.to_bytes(), signature)
    }
}

/// The challenge and the exporter are this connection's binding.
impl fmt::Debug for BotAuthTranscript<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            server_id,
            challenge: _,
            exporter: _,
            bot_pub,
        } = self;
        f.debug_struct("BotAuthTranscript")
            .field("server_id", server_id)
            .field("challenge", &"<redacted>")
            .field("exporter", &"<redacted>")
            .field("bot_pub", bot_pub)
            .finish()
    }
}

/// The public key of an Ed25519 key pair made from OS randomness whose
/// secret is dropped at once (§ 6.16): a bot re-keyed when its creator was
/// removed authenticates with no key anyone holds, until `rotate_bot`.
/// `None` when the OS has no randomness. The seed is `Zeroizing`; the
/// expanded `SigningKey` dropped here is wiped by ed25519-dalek's `zeroize`
/// feature, which the workspace enables (Cargo.toml) and must keep.
pub fn unheld_key() -> Option<[u8; 32]> {
    let secret = random().ok()?;
    Some(SigningKey::from_bytes(&secret).verifying_key().to_bytes())
}

fn random() -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    let mut bytes = Zeroizing::new([0; 32]);
    getrandom::fill(&mut bytes[..]).map_err(|_| IdentityError::Rng)?;
    Ok(bytes)
}

/// HKDF-SHA256 (RFC 5869): extract with `salt` over the 32-byte `secret`,
/// expand with the server id's ASCII to 32 bytes (one block), used as the
/// Ed25519 secret key (RFC 8032). Written on hmac, whose state and outputs are
/// zeroized on drop; the hkdf crate keeps its PRK in a value it never clears.
fn derive(secret: &[u8; 32], salt: &[u8], server_id: &ServerId) -> SigningKey {
    let mut extract = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC takes any key length");
    extract.update(secret);
    let prk = extract.finalize();
    let mut expand =
        Hmac::<Sha256>::new_from_slice(prk.as_bytes()).expect("HMAC takes any key length");
    expand.update(server_id.as_bytes());
    expand.update(&[1]);
    let okm = expand.finalize();
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(okm.as_bytes());
    SigningKey::from_bytes(&key)
}
