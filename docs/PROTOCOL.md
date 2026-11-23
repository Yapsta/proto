# Yapsta native protocol

The specification of Yapsta's native protocol, ALPN `yapsta/1`: transport and
framing, identity and authentication, events and sync, voice, files, media and
every feature's commands, requests and events. This crate (`yapsta-proto`) is
its single source of the wire format; `proto/yapsta/v1/yapsta.proto` holds the
exact messages and field numbers.

This document was section 6 of the Yapsta server's design document, and it
keeps that numbering (§ 6.1 to § 6.18) so references from code and from the
server, client and bot repositories stay valid. References to other sections
(§ 3, § 4, § 5, § 7 to § 13) and to `crates/…` or `docs/…` paths point into
the server repository (Yapsta/server, `docs/ARCHITECTURE.md`): they describe
how the server implements a rule, not the wire format itself.

The wire surface is add-only (§ 6.7): fields and enum values are added, never
renumbered, retyped or repurposed. A change to this document that changes
behaviour on the wire ships in a release of this repository first; the server
and clients then move to that release's tag.

## 6. Native protocol

### 6.1 Transport and framing

| Traffic | Carrier |
|---|---|
| Control: commands, events, acks | One bidirectional QUIC stream per session (the "control stream") |
| Request/response (history page, search, member page, file metadata) | One short-lived bidirectional stream per request |
| Ephemeral events (typing, presence; speaking is derived from voice, § 6.10) | Control stream, no `seq` (§ 6.3) |
| Voice | QUIC DATAGRAM (RFC 9221), § 6.4 |
| Files | One unidirectional stream per transfer; signed HTTPS URLs for large files (§ 6.5). M3: requests for files up to 1 MiB − 4 KiB and signed HTTPS URLs above that, on both transports; no unidirectional streams yet (§ 6.9) |
| Screen share / video | WebRTC (DTLS-SRTP) to the SFU on the media port, UDP or ICE-TCP; signalling on the control stream (§ 6.6) |

- **Framing:** each frame is a `u32` big-endian length plus a protobuf `Envelope`. The length counts the `Envelope` bytes only.
  - Max frame: 16 MiB for reply frames on QUIC request streams, 1 MiB for every other frame (the control stream, TCP, and the request frame a client sends first on a request stream). From M9 a frame the client sends before its `Welcome`, and every frame of a non-member session, is at most 32 KiB (§ 6.16); a legal `Auth` without capabilities is under 18 KiB (a 16 KiB device-list body, keys, signatures, `client_info` and a resume token); from M9 `Auth.capabilities` and `Hello.capabilities` hold at most 64 entries (`INVALID` otherwise), so the largest legal `Auth` stays under 18 KiB. The limit is checked on the length prefix, before any read or decode. A larger frame is `TOO_LARGE`.
  - **Partial frames (M9):** before its `Welcome`, and for the whole of a non-member session, once a frame's first byte has arrived on the control stream the whole frame (at most 32 KiB) must arrive within 10 s, on QUIC and on TCP; otherwise the connection closes with `INVALID`, as for a frame that does not decode (§ 6.16). Members' frames have no such clock: a slow 1 MiB upload over TCP stays within § 6.5's progress floor.
  - The server opens the control stream (the first server-initiated bidirectional stream) right after the TLS handshake and writes `Hello` on it. The client opens request streams, and only after a **member** `Welcome` (M2: the handshake's, or the one that answers a `Redeem`, § 6.2): until then a client may open no streams at all (QUIC stream limits 0). The server then raises the limit to 64 bidirectional streams. Non-members never get request streams. A connection may have at most 4 MiB in flight to the server, all streams together. Reading a frame returns flow-control credit, so the server also keeps a per-connection **budget** of 4 MiB and allows at most 64 outstanding requests (QUIC: the stream limit; TCP: at 64 the server deliberately stops reading the TLS stream until one is answered, so TCP flow control holds the rest; the 60 s receive timeout is suspended meanwhile, and clients read independently of writing):
    - A request frame takes its length from the budget after its prefix is read and before its body is, and gives it back as soon as the frame is decoded. From M9 a `Command` frame on the control stream counts its decoded length against a separate per-connection **command allowance** of 4 MiB, from when it is read until the command has run, so commands queued behind a slow one are bounded (§ 6.16). The allowance never waits on reply reservations: downloads in flight never hold up a command. Only a member's own queued commands can fill it: the server stops reading the control stream while the commands counted plus one frame of the largest size (1 MiB) would pass it, so they never do, until one has run (QUIC and TCP flow control hold the rest), with the 60 s receive timeout suspended meanwhile, as at 64 outstanding requests. No command is refused for it.
    - Then the request's read-only checks run (§ 6.8 order: the object exists and is visible, the values are in range), and before anything is committed it reserves its reply's worst case: for a visible `fetch_blob` the blob's stored size + 1 KiB, for `member_page` 1 KiB × `limit` (already checked to be at most 1,000), for `upload_image` 64 B, and for the M3 requests what § 6.9 states. A missing or hidden blob reserves nothing and is answered `NOT_FOUND`, so budget never tells the two apart. The reservation comes back once the reply is written. A request refused for budget has committed nothing and had no side effect. A reply frame is at most 4 MiB, so it always fits the budget (every M2 reply is at most about 1 MiB).
    - On QUIC both steps wait for budget; unread bytes stay in QUIC flow control. On TCP no request waits for budget, because that would stall the control stream: a request frame that cannot get budget is read and discarded in small chunks, and a request whose reply cannot be reserved is not run; both are answered `RATE_LIMITED` with `retry_after_ms`. Such a refusal takes no budget and counts as an outstanding request until it is written, so refusals stay within the 64. TCP reply frames are bounded by the budget, not counted as `outbound_queue` slots.
- **Envelope:**
  ```
  Envelope {
    request_id: u32 = 1      // 0 = none. Set on requests, commands that want a reply, and every frame of the reply
    last: bool = 2           // true on the final frame of a reply
    body: oneof {
      error: Error = 3
      hello: Hello = 4
      auth: Auth = 5
      welcome: Welcome = 6
      event: Event = 7               // persistent, carries seq (§ 6.3)
      ephemeral: Ephemeral = 8       // no seq (§ 6.3)
      set_presence: SetPresence = 9
      ack: Ack = 10                  // empty success reply
      ping: Ping = 11                // replied to with Ack; keepalive on TCP
      // M2 (minor 2):
      redeem: Redeem = 12            // non-member → member (§ 6.2)
      resync: Snapshot = 13          // a live session's view reset (§ 6.3)
      command: Command = 14          // management, control stream (§ 6.8)
      command_result: CommandResult = 15
      request: Request = 16          // request streams (§ 6.8)
      response: Response = 17
    }
  }
  ```
  - `Command`, `CommandResult`, `Request` and `Response` each wrap one `oneof kind`. A `Command` or `Request` whose `kind` is unset or unknown is answered with `INVALID`, like an unknown body. Clients ignore an unknown `CommandResult` or `Response` kind.
  - The client picks `request_id`. It is unique among the client's open requests on the connection, commands on the control stream included.
  - On a QUIC request stream, the first frame carries the request. The client writes it as soon as it opens the stream. Every reply frame repeats the `request_id`. The server finishes the stream after the frame with `last = true`.
  - An unset or unknown `body` (a newer peer's variant) is not an error for clients: they ignore it. The server answers it with `INVALID` when `request_id` ≠ 0 and ignores it otherwise. Unknown variants inside `Event` and `Ephemeral` are ignored the same way.
  - Field numbers are allocated in order and never reused. Retired numbers and names are `reserved` (§ 6.7).
- **Errors:** `Error{code: ErrorCode, message: string, retry_after_ms: optional u64}`. `message` is fixed server text for people to read, at most 256 bytes. It never holds user content, and clients never parse it. The codes are stable API, and each code is also the connection close code:

  | # | Code | Meaning | Closes the connection |
  |---|---|---|---|
  | 0 | `UNSPECIFIED` | Normal close. Never sent in an `Error` | Close code only |
  | 1 | `UNAUTHENTICATED` | Bad signature or device-list signature; no `Auth` within 10 s; a frame other than `Auth` before `Welcome`; from M9 a non-member session still without a membership 120 s after its `Welcome` (§ 6.16) | Yes |
  | 2 | `FORBIDDEN` | Not allowed for this member | No; from M9 yes for a non-member's body other than the few it may send (§ 6.2) |
  | 3 | `NOT_FOUND` | No such object, or not visible | No |
  | 4 | `RATE_LIMITED` | Limit hit; `retry_after_ms` set | Yes for the failed-`Auth` limit and, from M9, the non-member session caps (§ 6.16); otherwise no |
  | 5 | `INVALID` | Malformed request, field out of bounds, frame that does not decode | Yes when the frame does not decode; otherwise no |
  | 6 | `CONFLICT` | State conflict; a device list with the stored version but different devices (§ 6.2) | Yes for the device list; otherwise no |
  | 7 | `TOO_LARGE` | Frame or upload over its limit | Yes on the control stream and TCP; a QUIC request stream is reset instead |
  | 8 | `UNAVAILABLE` | Shutting down or overloaded; `retry_after_ms` may be set. Also a command's reply when something it needs is not there right now (media, § 6.6; an offline bot, § 6.15) | Only when the server closes the connection (shutdown, overload); a command's or request's reply leaves it open |
  | 9 | `SLOW_CONSUMER` | Outbound queue overflow. The client resumes | Yes |
  | 10 | `UNSUPPORTED_VERSION` | No common minor version (§ 6.7) | Yes |
  | 11 | `DEVICE_NOT_LISTED` | `device_pub` is not in the stored list, or a newer list removed it | Yes |
  | 12 | `DEVICE_EXPIRED` | The device entry expired, at `Auth` or during the session | Yes |
  | 13 | `SESSION_REPLACED` | The same device authenticated on a newer connection | Yes |
  | 14 | `MEMBER_REMOVED` | The account is no longer a member: transferred (§ 6.8), and from M6 kicked or banned. Sent to each of its sessions (M2) | Yes |

  - **Closing over QUIC:** the server writes the `Error` on the control stream and finishes the stream. Then it closes the connection with the code as the QUIC application error code and an empty reason phrase, once the stream is acknowledged or after 1 s. A client that never received the frame uses the close code. A connection the server closes before it has written anything (a stop while the connection is still being set up) gets the close code alone, with no frame. If that happens before the handshake is confirmed, the close also travels in the Handshake space, where QUIC turns any application code into the transport error `APPLICATION_ERROR` (RFC 9000 § 10.2.3). A client then sees that error and no code. An attempt that arrives as the stop begins, before its handshake starts, is refused (QUIC `CONNECTION_REFUSED`). Connection attempts refused before the handshake (§ 9) get QUIC `CONNECTION_REFUSED` and no application code.
  - **Closing over TCP:** the server writes the `Error` frame, flushes, and sends TLS `close_notify`. An EOF without `close_notify` counts as a lost transport, and the client resumes.
  - A peer abandoning a QUIC request stream resets it with code 0. The server resets a request stream with the `ErrorCode` of its failure.
- **Keepalive:** QUIC keepalive every 15 s; idle timeout 60 s, set on both peers (the quinn defaults are 30 s and none). On TCP the client sends `Ping` after 15 s without sending anything, and either side closes after 60 s without receiving a frame.
- **Backpressure:** each connection has a bounded outbound event queue (default 2048, `outbound_queue`). If it overflows, the server disconnects with `SLOW_CONSUMER` and the client resumes.
  - A frame the peer does not take within 60 s also closes the connection with `SLOW_CONSUMER`.
- **ALPN:** `yapsta/<major>`, now `yapsta/1`, on QUIC and on TCP. After the handshake the server checks the negotiated protocol on both transports. A connection without it is closed without a frame (rustls proceeds when a TCP client offers no ALPN at all). The minor version is negotiated in the handshake (§ 6.7).
- **No 0-RTT:** early data is disabled (`max_early_data_size = 0`), because `Auth` must be bound to the post-handshake exporter (§ 6.2).
- **TCP fallback (TCP 7120):** TLS 1.3, the same certificate and ALPN as QUIC. The TLS stream is the control stream, with the same frames and handshake.
  - Requests that use their own QUIC streams are multiplexed on it: same `Envelope`, tagged by `request_id`, the reply ending at `last = true`. The 1 MiB frame limit applies to every frame, so replies of more than 1 MiB are split into frames of at most 1 MiB. The server interleaves at frame boundaries and sends control frames first.
  - A client cannot cancel a request over TCP in M1. It drops frames for a `request_id` it has abandoned.
  - Each frame is flushed when written.
- **Ports:**

  | Port | Use |
  |---|---|
  | UDP 7120 | QUIC |
  | TCP 7120 | TLS fallback: control and requests on one stream. No voice (P2), no file streams (use HTTPS URLs) |
  | TCP 7121 | HTTPS (`https_listen`): file URLs (§ 6.5, M3); from M6 the admin API, `/metrics` and the panel, all but the panel's assets behind admin auth (§ 6.13). Use a reverse proxy for 443 |
  | UDP 7122 | SFU media, one port for every track (`media_udp_listen`), from M7 (§ 6.6) |
  | TCP 7122 | SFU media over ICE-TCP for networks that block UDP (`media_tcp_listen`), from M7 |

- **URL scheme:** `yapsta://host[:port][/invite/<code>]`.

### 6.2 Identity, devices, authentication

**Seed and per-instance keys**
- A person has an **identity seed**: 32 random bytes, shown once as a 24-word **recovery phrase**.
- For each instance, the client derives an **account key**: `Ed25519(HKDF-SHA256(seed, salt="yapsta/account/v1", info=server_id))`.
  - Precisely: HKDF-SHA256 extract with salt = the 17 ASCII bytes `yapsta/account/v1` and IKM = the 32-byte seed. Then expand with `info` = the 26 ASCII bytes of `server_id` to 32 bytes. Those 32 bytes are the Ed25519 secret key (the RFC 8032 seed form, not the 64-byte keypair form). Test vector: seed `00 01 … 1f` and `server_id` `a5jy5opmsxgrcsn22buvxzm5qi` give the secret key `fe86c8f552bdedd60cbd7cc0f2a7d1d1568df772f6638c32b6f4c06f54add610` and `account_pub` `120224b63eda1adfea27dcf54ec77523b9112693248cd393f76e196741d83455`. The same 32 bytes as a device secret on that `server_id` give `device_pub` `f79e984d99dac8855b8134d801aceafd48c884bba3f29e98d907af5142d92af4`. `yapsta-proto`'s `identity` module is the shared implementation.
  - The recovery phrase is the BIP-39 English mnemonic of the 32 seed bytes as entropy (24 words). It is not the BIP-39 PBKDF2 "seed".
  - Each instance sees a different public key, so instances can't link a person's accounts.
  - People link their accounts across servers themselves, through client-side contacts.

**Devices**
- Each device has a **device secret** (32 random bytes) and, per instance, a **device key**: `Ed25519(HKDF-SHA256(device_secret, salt="yapsta/device/v1", info=server_id))`, derived like the account key (below). Each instance sees a different `device_pub`, so device keys cannot link a person's accounts across instances either.
- An instance accepts a device only if it is in the account's current **device list**:
  ```
  SignedDeviceList{body: bytes = 1, signature: bytes = 2}
  DeviceListBody{version: u64 = 1, devices: [DeviceEntry] = 2}
  DeviceEntry{device_pub: bytes(32) = 1, expires_at: u64 = 2}   // expires_at: unix seconds
  ```
  `body` is the encoded `DeviceListBody`, exactly as signed. The account key signs it (see the signed byte strings below). The list holds no device names: names stay on the person's own devices.
  - Receivers verify the signature over the bytes they received, then decode `body`. Nobody re-encodes a body to verify or forward it.
  - Limits: `version` ≥ 1; at most 64 entries; no duplicate `device_pub`; `body` at most 16 KiB, refused before it is hashed or decoded (a full list is about 3 KiB; the rest is room for fields a later version adds).
- **The stored list is the authority.** The server stores, for members (§ 7.1), the highest `SignedDeviceList` it has accepted, as received. Every `Auth` presents a list; the server compares its version with the stored one:
  - Higher: it replaces the stored list in one transaction (after the checks in the handshake). Live sessions of devices it no longer lists are closed with `DEVICE_NOT_LISTED`.
  - Equal with the same bytes, or lower: the presented list is ignored, and the device is checked against the stored list. So a seedless device that never saw a renewal keeps working while the stored list still lists it unexpired.
  - Equal with different bytes: rejected with `CONFLICT`, and that `Error` carries the stored list in `device_list`. The client merges it, signs a higher version and authenticates on its next attempt.
  - Not in the stored list (or no list stored and not in the presented one): `DEVICE_NOT_LISTED`. When the presented list verified under `account_pub`, that `Error` carries the stored list in `device_list`: a seed device restored from its phrase has a new device key and no record of the stored version (it presents version 1, so it gets `DEVICE_NOT_LISTED` or, against a stored version 1, `CONFLICT`), so it merges the stored list, adds itself, signs stored version + 1 and authenticates on its next attempt. `DEVICE_EXPIRED` carries the stored list the same way: a seed device whose entry expired in a newer stored list (its own newer-than-it-knew list is ignored as lower) merges it with a fresh entry for itself and signs stored version + 1. A seedless or revoked device learns only public device keys and expiries of an account it presented, and can sign nothing.
  - `Welcome` returns the stored list to members' devices, so seedless devices pick up renewals and seed devices merge before signing a new version.
  - Connections of non-members store nothing. They verify the presented list, and an account that has a stored list (a former member, § 6.2 Membership and identity) is checked against it.
  - `version` is a per-instance counter: a seed device signs the stored version + 1. It is never a timestamp, so versions don't correlate across instances.
- **Device certificates expire after 90 days.** A list is rejected (`INVALID`) if any entry has `expires_at` > server now + 90 days + 300 s. Entries that have already expired may stay in the list, but those devices cannot authenticate (`DEVICE_EXPIRED`). A live session is closed with `DEVICE_EXPIRED` when its entry expires. Clients add a random jitter of up to 24 h per instance to `expires_at`, so the values don't correlate across instances.
- **Renewal** uses no separate message: a seed-holding device signs a higher version with fresh `expires_at` for itself and for the seedless devices it vouches for, and presents it in its next `Auth`. Clients renew when an entry has fewer than 30 days left. Renewing during a session is a later capability (§ 6.7).
- **Which devices hold the seed:**
  - Desktop devices hold the seed by default.
  - Linked devices can be **seedless** (e.g. a phone). They hold only a device secret and need a seed-holding device for renewal.
  - Linking: the new device shows a QR code with a one-time link key. The seed device scans it, and the two open a direct encrypted channel keyed by the QR. Then either:
    - (a) the seed device sends the `server_id`s of its known instances, the new device returns its per-instance `device_pub`s, and the seed device adds them to each instance's list; or
    - (b) for a seed-holding link, the seed device transfers the seed.
- **Revocation:**
  - A new device list (higher version) without the lost device takes effect on each instance when any of the person's devices next connects to it.
  - Certificate expiry bounds the window for instances the person hasn't visited since.
- **Losing every device:** the recovery phrase restores the seed.
- **Losing the phrase too:** the space owner can transfer a member's roles and nickname to a new identity (an audited action, M2). The old account is banned.

**Server identity**
- `server_id = base32(sha256(TLS SubjectPublicKeyInfo))[..26]`, precisely: SHA-256 over the DER bytes of the leaf certificate's SubjectPublicKeyInfo; RFC 4648 § 6 base32 alphabet, lowercased, no padding; the first 26 characters (130 bits). It is the HKDF `info` as its ASCII bytes. Test vector: the 28 ASCII bytes `yapsta server_id test vector` in place of the SPKI give `a5jy5opmsxgrcsn22buvxzm5qi`. Clients recompute it from the pinned SPKI rather than trusting `Hello`.
- Clients pin the **SPKI** on first use (TOFU). ACME certificates are renewed with the **same key**, so the pin survives renewals. A changed SPKI is a hard warning.

**Handshake** (control stream, after TLS 1.3)
1. The server sends `Hello{server_id, versions, challenge: 32B, capabilities, space_public_info}`.
   - `versions`: the minor versions it accepts, highest first (§ 6.7). `challenge`: 32 bytes from the OS RNG, fresh per connection.
   - `space_public_info` is sent empty in M1. From M2 it carries `SpacePublicInfo{name = 1, description = 2, rules = 3, icon_id: optional u64 = 4, claimed: bool = 5}` (`claimed`: the space has an owner; while false only the claim code can be redeemed). M5 adds `style: SpaceStyle = 6` (§ 6.11).
2. The client sends `Auth{version, credential: DeviceCredential{account_pub, device_list: SignedDeviceList, device_pub, signature}, capabilities, client_info, presence?, resume?: {token, last_seq}}` within 10 s, or the server closes with `UNAUTHENTICATED`.
   - `credential` is a oneof so that M8 could add a bot's credential beside `DeviceCredential` (§ 6.7 forbids moving fields into a oneof later): `BotCredential{bot_pub, signature}` (§ 6.15). The exact messages and field numbers are `proto/yapsta/v1/yapsta.proto` in this repository.
   - `version` is the highest entry of `Hello.versions` the client speaks. If there is none, the client closes with `UNSUPPORTED_VERSION`. The server closes with the same code if `version` is not in its list.
   - `signature` is the device key's Ed25519 signature over the `Auth` transcript below.
   - Binding to the TLS exporter means a relayed handshake fails. A fresh challenge means a replayed one fails.
   - A resume token alone is never enough: every connection signs.
   - `client_info{name, version}`: at most 64 bytes each, held in memory for the session, never persisted or logged.
   - `presence`: the initial account status (§ 6.3), so an invisible person never shows online on reconnect.
3. The server checks, in order: lengths (keys 32 bytes, signatures 64), `verify_strict` of `signature`, `verify_strict` of the device list against `account_pub`, the list's limits and 90-day cap, the device's entry and expiry, the version against the stored one. Then it sends `Welcome{session_id, account_id?, membership: Member?, resume_token?, device_list?, state: Snapshot | Resumed}`.
   - Keys with a weak (small-order) point are rejected, and keys are compared by their 32 canonical bytes.
   - Non-members get no `account_id`, no `membership`, no `resume_token` and no `device_list`.
   - Members also get `device_list: SignedDeviceList`, the stored list (above).

**Signed byte strings.** Every signature covers a domain prefix (ASCII, then one `0x00` byte) followed by fixed fields. Nothing signed is a re-encoded protobuf.

| Signature | Key | Signed bytes |
|---|---|---|
| Device list | account key | `yapsta/device-list/v1` `0x00` ‖ `body` (as carried) |
| `Auth` transcript | device key | `yapsta/auth/v1` `0x00` ‖ `server_id` (26 ASCII bytes) ‖ `challenge` (32) ‖ `exporter` (32) ‖ `account_pub` (32) ‖ `device_pub` (32) |
| Bot `Auth` transcript (M8, § 6.15) | bot key | `yapsta/bot-auth/v1` `0x00` ‖ `server_id` (26) ‖ `challenge` (32) ‖ `exporter` (32) ‖ `bot_pub` (32) |

- `exporter` is the TLS 1.3 exporter on this connection: label `yapsta-auth` (11 ASCII bytes), an **empty** context, 32 bytes. With quinn that is `export_keying_material(out, b"yapsta-auth", b"")`; with rustls over TCP, `Some(b"")`. The label and context are identical over QUIC and TCP, so one verifier serves both.
- `server_id` is the value the client recomputed from the pinned SPKI, never the copy in `Hello`. `account_pub` stops a device key from being presented under another account. All fields have a fixed length, so the concatenation is unambiguous.
- A new signature format gets a new prefix (`…/v2`) behind a capability. A `v1` string never changes.

**Account id.** `account_id` is a server-assigned `u64`, the `accounts` row id. It is created when an account first becomes a member (M2: claim or invite; M1: the test fixture), is stable for the account's life (also after it is removed from the space), and is never reused. It is not derived from the key, so it reveals nothing about `account_pub`.

**Capabilities.** `capabilities` (in `Hello` and `Auth`) is `repeated Capability`, a protobuf enum with `CAPABILITY_UNSPECIFIED = 0`. A feature is on only when both sides list it. Unknown values are ignored. M1 defines none; M10 defines `PUSH = 1` (§ 6.18).

**Non-members** (`membership: None`) can only:
- read `space_public_info` (name, icon, description, rules);
- redeem an invite;
- redeem the owner claim code;
- from M7, join a space whose owner opened it (§ 6.14).

New instances are invite-only; from M7 the owner may open the space (§ 6.14).

**Redeem (M2).** A non-member session sends `Redeem{oneof code{claim_code: string = 1; invite_code: string = 2}}` (M7 adds `open_join = 3`, § 6.14) with a `request_id` (from M6 a member may send it with a claim code, below). The only other bodies a non-member may send are `Ping` and the `Command` kind `fetch_space_icon` (§ 6.8); anything else is `FORBIDDEN` and, from M9, closes the connection, as does a frame that does not decode (§ 6.16). A non-member session ends 120 s after its `Welcome` unless a `Redeem` has made it a member (`UNAUTHENTICATED`; a client that is still choosing reconnects), and the server holds at most 256 non-member sessions in all and 4 per address key: an `Auth` that would pass either is closed with `RATE_LIMITED` and `retry_after_ms` instead of a `Welcome` (§ 6.16).
- `Redeem` is valid only on the control stream of a session whose `Welcome` answered a fresh `Auth` on this connection.
- **Rate limit first.** A `Redeem` takes a token from the `rate_redeem_fail_per_min` bucket of its address key (§ 5) before any lookup or hash, and gets it back on success. An empty bucket is `RATE_LIMITED` with `retry_after_ms` (the connection stays open). An open join takes from its own bucket instead and never gets it back (§ 6.14).
- **Bans first.** An account in `bans` (§ 7.1), or from M6 queued in `erasures` (§ 6.13), gets `FORBIDDEN` before the code is looked at, and again inside the transaction that would create the membership (§ 6.12).
- **Claim code:** 16 bytes (128 bits) from the OS RNG, valid only while the space has no owner. It is verified with argon2id off the tokio workers, at most 2 hashes at once (one pool shared with channel passwords, § 6.8). From M9 claim-code hashes take at most one of the two places, so channel passwords and admin and webhook tokens always find the other, and an attempt turned away because the pool's queue is full keeps its rate-limit token (§ 6.16). Its `owner_claim` row is deleted in the transaction that sets the owner.
- **Invite code:** looked up by its SHA-256 (§ 7.6); what a redemption does is in § 6.8.
- An unknown, expired, used-up, revoked or already-redeemed code gets one reply, `NOT_FOUND` with the same message, whichever it was. Codes are secrets (§ 7.6): never logged, never in `Debug`, never in `Error.message`.
- **Upgrade in place.** On success, in the transaction that creates the membership, the server applies the § 6.2 device-list rules again to the list presented at `Auth` (kept as received for this; time has passed), storing it as received when no list is stored yet; `CONFLICT`, `DEVICE_NOT_LISTED` and `DEVICE_EXPIRED` carry the stored list and close the connection, as at `Auth`. A refused `Redeem` uses no invite. Then it commits the membership (reusing the account's `account_id` when it has an `accounts` row), publishes `MemberJoined` (and for a claim `SpaceUpdated` with the new owner), and replies with a second `Welcome` on the `Redeem`'s `request_id` with `last = true`. That `Welcome` is a member's: `account_id`, `membership`, `resume_token`, `device_list` and `state: Snapshot`. The connection is now a member session: no new `Auth` (it already signed this connection's challenge), and request streams open (§ 6.1). The `session_id` stays the same.
- A connection or an account that is already a member gets `CONFLICT` for an invite `Redeem` (the connection stays open). From M6 a member on a minor-6 connection may redeem the claim code (valid only while the space has no owner, e.g. after `reset-owner`, § 6.13; on minor 5 it stays `CONFLICT`, § 6.7), on the connection it has, whether it was a member at `Auth` or became one by a `Redeem` on it: the claim is checked as for a non-member, and on success the member becomes the owner in the same transaction that deletes the `owner_claim` row, keeps its membership, and gets an `Ack` instead of a second `Welcome`; `space_updated` with the new owner is published, as for an ownership transfer (§ 6.8). Of the upgrade in place above, only the owner change applies: the device list is not checked or stored again, no `MemberJoined` is published, and no second `Welcome` is sent. No audit entry is written, as for the first claim; the `RESET_OWNER` entry before it records the operator's step.

**Membership and identity (M2).** An `accounts` row is an identity the space has known; a `members` row (§ 7.1) is the membership. An account removed from the space (transfer, from M6 kick or ban) keeps its `accounts` row and its stored device list but loses its `members` row, so a later `Auth` makes it a non-member, and its `account_id` is never reused. An `Auth` from an account with a stored device list is checked against that list by the § 6.2 rules whether or not it is a member; only the storing of a higher version waits for a membership. Bans are keyed on `account_id`. Removing an account closes all its sessions with `MEMBER_REMOVED` and drops its resume tokens in the same apply step (§ 4).

**Bots** (M8, § 6.15) authenticate with `Auth.credential.bot`: a key derived from a seed shown once at creation, which signs the bot `Auth` transcript (below) exactly as a device key signs its own. The server stores only the public key, so it holds nothing secret for a bot and runs no argon2 at `Auth`.

**Bootstrap**
- `yapsta-server init` creates the data directory and TLS key, and prints a one-time **owner claim code**. It lasts 24 h and can be re-issued with `yapsta-server claim-code`.
- The container image runs `yapsta-server run --init-if-needed`: the first start of an empty volume runs `init` first, so the fingerprint and claim code appear once in `docker logs`; later starts just run. If `init` fails (including a second container racing the first on the same volume), the start fails rather than running beside another process. That guards one start only: a restart policy would bring the loser back as a second server, so one volume backs exactly one container.
- The code stays in the container's log (and in any log shipping set up for it) until it is redeemed or the container is removed. When logs leave the host, redeem it promptly or re-issue it, which invalidates the logged one.
- `claim-code` writes to the database, so run it with the server stopped, never beside it (`docker exec` would make a second writer process; from M6 it refuses while `run` holds the data-directory lock, § 6.13): `docker stop c && docker run --rm --network none -v <volume>:/data <image> claim-code && docker start c`.
- The first account to redeem it becomes the **space owner**.
- From then on, all space management happens through the protocol: in `yapsta-cli` (M1/M2), and in Yapsta Client.

### 6.3 Events, sync, resume

- **Persistent state events** (message created, channel updated, member joined, role changed, voice state changed, …):
  - They carry a per-space `seq`, assigned at commit (§ 4).
  - Each client only receives events about things it can see.
- **Ephemeral events** (typing, presence changes) have no `seq` and are never replayed. Speaking indicators are derived by clients from the datagrams they receive (§ 6.10).
- **Personal events** (DMs, DM read states, blocks, and from M10 notification settings, § 6.17, § 6.18) concern one account, not the space. From M10 (minor 10) they travel on a personal stream of their own, never as an `Event`, so they never touch the space `seq` (below, "Personal stream, M10"). Channel read states keep their M3 path for every minor: an ephemeral to the account's other sessions plus the `Snapshot` and `Resumed` fields (§ 6.9); M10 does not change them.
- **Snapshot on connect:**
  - It contains the space, the visible channels, roles, your permissions, the members currently online in visible channels, voice states and unread markers. From M10 personal state (DMs, blocks, notification settings) comes in a personal snapshot of its own (below).
  - It contains no message history. History is fetched per channel through request streams.
- **Member lists:** large spaces get online members only, and offline members are paged.
- **Resume:**
  - The server keeps an in-memory ring of recent space events (default: 10 min or 50,000 events).
  - On resume, it replays events after `last_seq` if:
    - they are still in the ring, and
    - the client's visibility didn't change in the gap.
  - Otherwise, it sends a fresh snapshot. A visibility change is any role, overwrite or membership event affecting the account.
  - The ring doesn't survive a restart. After a restart, clients get a snapshot.
  - `seq` is a `u64` per space, allocated in commit order by the single writer. It is not persisted in M1 and restarts with the process. A snapshot carries the current `seq` and resets the client. Clients never compare `seq` across snapshots.
  - Clients record the `seq` of every `Event`, including kinds they don't know, and send the highest as `last_seq`.
  - The server replays events with `seq` > `last_seq`. If `last_seq` is ahead of the current `seq`, it sends a snapshot. Resume never fails with an error: every fallback is a snapshot.
  - After a replay, `Resumed` carries the current presence of online members, because ephemeral events are not replayed.
- **Resume tokens:**
  - 32 bytes from the OS RNG, opaque to the client. The server keeps only the token's SHA-256, in memory, and never logs either.
  - Only members get one. Each token is bound to (`account_pub`, `device_pub`), and an `Auth` from any other pair ignores it.
  - Single use: the `Auth` that presents a token consumes it, whether it resumes or falls back to a snapshot.
  - Rotated: every `Welcome` issues a new token and invalidates that device's previous one.
  - A token expires `resume_ring_secs` after its session ends, and on restart.
  - A device that authenticates again closes its older session with `SESSION_REPLACED`.
- **Presence** (ephemeral):
  - The account status is `ONLINE`, `IDLE`, `DND` or `INVISIBLE`. It is set by `Auth.presence` or `SetPresence` from any of the account's devices, applies to all of them (last write wins), and is held in memory while the account has a session.
  - Each session also reports `afk: bool` through `SetPresence`. `custom_status` is at most 128 bytes of UTF-8 (empty clears it), and in M1 it is held in memory only.
  - Members see the aggregate:
    - `OFFLINE` with no session, or when the status is `INVISIBLE`;
    - otherwise `DND` if the status is `DND`;
    - otherwise `IDLE` if the status is `IDLE` or every session is afk;
    - otherwise `ONLINE`.
  - `PresenceUpdate{account_id, status, custom_status}` goes to members only, when the aggregate or the custom status changes, at most once per second per account (the latest wins). `OFFLINE` and `UNSPECIFIED` are invalid in `SetPresence` (`INVALID`).
- **M1 events and snapshot:**
  - The only persistent event type in M1 is `MemberJoined{member: Member{account_id, joined_at}}` in `Event{seq, kind}`. M2 emits it for claims and invites. In M1 the test fixture emits it, going through the normal validate → commit → apply → publish path (§ 4).
  - The M1 snapshot is `{seq, member (own), presences (online members)}`. Later milestones add fields.
- **M2 events** (`Event.kind`, numbers continuing from `member_joined = 2`; shapes in § 6.8):

  | # | Kind | Message | Delivered to |
  |---|---|---|---|
  | 3 | `space_updated` | `SpaceUpdated{space: Space = 1}` (full form) | every member |
  | 4 | `channel_created` | `ChannelCreated{channel: Channel = 1}` | members with `VIEW_CHANNEL` on it |
  | 5 | `channel_updated` | `ChannelUpdated{channel: Channel = 1}` | members with `VIEW_CHANNEL` on it after the change; those who lose it get `channel_deleted` instead |
  | 6 | `channel_deleted` | `ChannelDeleted{channel_id: u64 = 1}` | every member (it carries only an id) |
  | 7 | `role_created` | `RoleCreated{role: Role = 1}` | every member |
  | 8 | `role_updated` | `RoleUpdated{role: Role = 1}` | every member |
  | 9 | `role_deleted` | `RoleDeleted{role_id: u64 = 1}` | every member |
  | 10 | `overwrite_set` | `OverwriteSet{overwrite: Overwrite = 1}` | members with `VIEW_CHANNEL` on its channel after the change; those who lose it get `channel_deleted` instead |
  | 11 | `overwrite_deleted` | `OverwriteDeleted{channel_id: u64 = 1, oneof target{role_id: u64 = 2; account_id: u64 = 3}}` | as `overwrite_set` |
  | 12 | `member_updated` | `MemberUpdated{member: Member = 1}` (full form) | every member |
  | 13 | `member_removed` | `MemberRemoved{account_id: u64 = 1}` (M6 adds `reason = 2`, § 6.12) | every member |

  `MemberJoined` (M1) now also carries the member's profile fields (§ 6.8). Roles and members are space-wide, so every member sees them; channels and overwrites follow `VIEW_CHANNEL`.
- **Filtering.** Each persistent event is filtered per recipient session against that session's set of viewable channels, computed by the § 8 engine and cached (§ 8.4). The sets are recomputed in the apply step of every change that can alter them, before that change's events are fanned out, whatever the `resync` throttle below. The filter runs where events are fanned out, before an event enters a session's outbound queue, so an event a session cannot see never takes a slot. Replays from the resume ring pass the same filter. An event filtered out for a session still advances `seq`; clients never assume consecutive `seq`.
- **Live resync.** When a committed **permission** change (`role_*` permissions or position, `overwrite_*`, the member's own roles, a channel move, an owner change) alters what a live session can see or do (its viewable channels, its base permissions or its per-channel permissions), the server sends that session `resync: Snapshot` after the events of the same commit, and only to sessions whose result actually changed. Creating, deleting or editing a channel never causes a `resync`: its event carries the change, and after `channel_created` each session that receives it also gets `Ephemeral.channel_permissions: ChannelPermissions = 2` with its own permissions on the new channel. The event and that ephemeral enter a session's outbound queue together: they take two slots (ephemerals count as `outbound_queue` slots like events), and are queued only when both are free (otherwise `SLOW_CONSUMER`, as for any overflow), written back to back. The shared parts of resync snapshots made in one apply step are encoded once. The client replaces its state with it, exactly as with a `Welcome` snapshot, and `seq` continues from `Snapshot.seq`. At most one `resync` per session per second; changes inside that window are folded into the next one. While a session owes a `resync` (throttled, or queued but not yet written), its resume token is marked, and a resume with a marked token is always answered with a snapshot, whatever `last_seq` says. The `channel_permissions` ephemeral after `channel_created` marks the token the same way until it is written.
- **Resume, M2.** A visibility change, for the resume rule above, is any `role_*`, `overwrite_*`, `channel_created` (also one whose `seq` equals `last_seq`, whose ephemeral may have been lost), `channel_deleted`, `member_updated` (from M9 only one about the resuming account itself or one that changes a member's roles, § 6.16; a profile, nickname or avatar change of another member is replayed like any event) or `member_removed` event, a `channel_updated` that moves a channel, or a `space_updated` that changes the owner, when it can affect the account (in M2 the server may treat every such event as affecting every account). From M2 a resume is also answered with a snapshot when the event at `last_seq` itself has left the ring, even if every later event is still there (stricter than the M1 rule above).
- **M2 snapshot** (`Snapshot`, fields continuing from `presences = 3`; objects in their snapshot form, § 6.8): `space: Space = 4`; `channels: repeated Channel = 5` (visible ones only, each with its overwrites); `roles: repeated Role = 6`; `members: repeated Member = 7` (online members only); `base_permissions: fixed64 = 8` (§ 8.2 step 1, for this account); `channel_permissions: repeated ChannelPermissions = 9` (`{channel_id = 1, permissions: fixed64 = 2}` for each visible channel).
- **Snapshot size.** The snapshot and every `resync` travel in one frame of at most 1 MiB. At the § 6.8 limits the worst case is about 0.65 MiB: 500 channels × ~100 B (no topic) ≈ 50 KB; 5,000 overwrites × ~30 B ≈ 150 KB; 250 roles × ~70 B ≈ 18 KB; 1,000 online members × (~120 B member + up to 50 role ids × ~3 B + ~170 B presence) ≈ 440 KB; 500 channel permissions × ~14 B ≈ 7 KB; the device list ≤ 16 KiB. Above 1,000 online, `members` and `presences` both list the first 1,000 online accounts by `account_id`, and the rest come through the member page, which carries presence too (§ 6.8). M3 adds at most about 25 KB: 500 read states × ~25 B ≈ 12 KB and 200 custom emoji × ~60 B ≈ 12 KB, so the worst case stays under 0.7 MiB.
- **M3** (§ 6.9): events 14–25, ephemerals 3–5, `Snapshot` fields 10–11 and `Resumed` field 2. Message events are filtered by their `channel_id` like any channel event (thread events by their thread's channel) and are not visibility changes, so they never turn a resume into a snapshot.
- **M4** (§ 6.10): event 26, ephemeral 6, `Snapshot` field 12. Voice state events are filtered by their channel and are not visibility changes. The snapshot grows by at most about 30 KB (1,000 voice states × ~30 B), so its worst case stays under 0.75 MiB; § 6.10 caps voice at 1,000 accounts per space.
- **M5** (§ 6.11): no new event or ephemeral kinds. `space_updated` carries the style and switches, and one that changes `voice_chat_access` is a visibility change for resume. Chat events of a voice channel under `MEMBERS_IN_CHANNEL` are filtered by readership (voice presence, or the owner and `MANAGE_MESSAGES` exemptions) as well as by the channel, live and in replays alike. The snapshot grows by a few bytes (the `Space` fields) plus at most 500 read states already counted under M3.
- **M6** (§ 6.12): no new event or ephemeral kinds. `member_removed` carries `reason`, and `Member` carries `timeout_until` wherever it travels; a timeout's set and clear are `member_updated`, and its expiry publishes nothing. The snapshot grows by at most about 6 KB (1,000 members × ~6 B). Erasure redacts the ring (§ 6.13).
- **M7** (§ 6.6, § 6.14): events 27–28, ephemeral 7, `Snapshot` field 13. Media track events are filtered by their channel like voice state events and are not visibility changes; they are small (ids and an enum) and count in the ring like any event. The snapshot grows by at most about 50 KB (two tracks for each of 1,000 accounts in voice × ~25 B), so its worst case stays under 1 MiB. Open join adds no event kind (`space_updated` carries it, § 6.14).
- **Personal stream, M10** (§ 6.17; minor 10 only):
  - **Carrier.** `Envelope.body` gains `personal: PersonalEvent = 19` (`PersonalEvent{seq: u64 = 1, oneof kind{…}}`, kinds in § 6.17) and `personal_snapshot: PersonalSnapshot = 20`. Only members of the space have a personal stream: a personal event goes to every live minor-10 member session of each account it concerns, and to nobody else; a non-member session (§ 6.2: public info only), even one whose account still has 1:1 DMs from an earlier membership, and a session of minor 9 or lower are sent neither body. A session that becomes a member through `Redeem` gets its personal snapshot then, built as the same sequenced step (below).
  - **`seq`.** Each account has its own personal `seq`, a `u64` allocated in commit order after the commit (§ 4), separate from the space `seq`. An account's counter is kept for as long as the process runs, even when nothing of it is left in the ring, so a value is never reused before a restart; it is not persisted and restarts with the process. A personal snapshot carries the current value and resets the client; clients never compare personal `seq` across personal snapshots.
  - **Personal snapshot.** `PersonalSnapshot{seq: u64 = 1, dms: repeated Dm = 2, dm_read_states: repeated DmReadState = 3, blocked_account_ids: repeated u64 = 4}` (§ 6.17; § 6.18 adds notification settings). A minor-10 session gets one right after `Welcome` (before any personal event), unless it resumes the personal stream (below). It replaces the client's personal state, and personal `seq` continues from its `seq`. It is built as a sequenced step, like the read-state load (§ 6.9), so every personal event committed after it reaches the session and none before it does: the handshake loads it through the writer, stamped with the account's personal `seq` in that step's place in commit order, and the session's registration sends it followed by the account's personal events committed since, from the ring. If the ring has lost those events by then (or the account was removed and joined again in between), the handshake loads again, up to three times, so a session that falls back to a snapshot, a resume included, gets a fresh one rather than an error; only if the account's stream keeps moving faster than a load does the handshake close with `UNAVAILABLE`, and the client reconnects, as when the read-state copy is missing. A personal resume that replays (below) uses no load. A space `resync` never touches personal state, and a personal snapshot never touches space state. It travels in its own frame of at most 1 MiB: at most the account's 500 most recently active DMs (older ones through `list_dms`, § 6.17) × ~200 B (a group DM of 10 ids and a 100-byte name) ≈ 100 KB, their read states × ~25 B ≈ 13 KB, and at most 1,000 blocked ids × ~5 B ≈ 5 KB, about 120 KB in all (§ 6.18's notification settings bring it to about 140 KB).
  - **Ring and resume.** The server keeps recent personal events in one ring for all accounts, in commit order, each entry tagged with its account and its personal `seq`: at most 1,000 entries per account (an account's oldest go first, so one busy account cannot push out the others), at most `resume_ring_events` entries and `personal_ring_bytes` (§ 5, default 16 MiB) of encoded events, none older than `resume_ring_secs`, the oldest evicted first. Every personal event enters the ring for each account it concerns, whether or not that account has a live session. `Resume` gains `personal_last_seq: optional u64 = 3`. The personal stream is resumed only with a valid resume token for this (account, device) (§ 6.3 "Resume tokens"; a token is gone after a restart), whether the space part then replays or falls back to a snapshot: then, if `personal_last_seq` is present and the ring still holds that account's event with that `seq` (or it equals the account's latest personal `seq`), the server replays the account's later personal events after `Welcome`. In every other case (no valid token, the field absent or ahead of the counter, the event evicted) it sends a personal snapshot. So with a valid token the space and personal decisions are independent: a space snapshot can come with a personal replay, and a space replay with a personal snapshot. A personal resume never fails with an error. The ring does not survive a restart. A removed or erased account's entries are dropped with its membership, and an account that leaves or is removed from a group DM has its entries dropped from the ring in the same apply step, before `dm_removed` is published (all of them, not only that DM's: an account's entries carry consecutive `seq`s, so a hole cannot be resumed past, and its next resume gets a personal snapshot), so neither a replay nor a later redaction (below) can bring it anything of that DM again.
  - **Redaction.** When a DM message is edited, deleted, pruned or erased (§ 6.17, § 6.13), the ring replaces its earlier `dm_message_created` and `dm_message_updated` entries, those of accounts that are still members of the DM, with a `dm_message_updated` carrying the new form (any other account's entries for it are dropped), keeping their `seq`, and its earlier reaction entries lose their `emoji`, as the space ring does (Ring size, M3, below).
- **M10** (§ 6.17, § 6.18): `Envelope.body` 19–20, `Resume` field 3, `Typing` field 4, `Welcome` field 8; personal event kinds and `PersonalSnapshot` fields are listed in § 6.17 and § 6.18. No new `Event` or ephemeral kind and no new `Snapshot` or `Resumed` field: DMs never enter the space stream, and space visibility never depends on them.
- **Ring size, M3.** Message events carry content, so the ring is bounded by bytes too: it keeps at most `resume_ring_bytes` of encoded events (default 32 MiB) besides `resume_ring_events` and `resume_ring_secs`, and evicts the oldest first; a resume whose `last_seq` event was evicted gets a snapshot (the M2 rule above). When a message is edited or deleted, the ring replaces that message's earlier `message_created` and `message_updated` events, each keeping its `seq`, with a `message_updated` carrying the new form (the edited message or the tombstone, § 6.9), re-encoded once and counted against `resume_ring_bytes`, so content removed from the database is not replayed either. A deleted or pruned message's earlier `reaction_added` and `reaction_removed` events keep their `seq` but lose their `emoji` (a tombstone has no reactions, and a Unicode reaction is user text). Since an edited form carries the reaction counts at the edit and replaces events from before it, a client takes a message event's counts over the reaction events before it. Pruning (§ 7.4) redacts the ring the same way for every message it removes (a message edited shortly before its deadline, or a channel whose retention was shortened, can still have entries there), so pruned content is never replayed either.

### 6.4 Voice

**Datagram header** (16 bytes, then the Opus payload):

```
u8  version(4) | flags(4): EOT (end of transmission), DTX
u8  codec: 1 = opus-voice (mono), 2 = opus-music (stereo)
u8  route: 0 = channel, 1 = whisper, 2 = direct (reserved)
u8  key_id: 0 = none (reserved for E2EE, § 7.6)
u16 seq
u32 timestamp (48 kHz sample clock)
u32 ref: C→S the sender's own session_ref (route 0) | whisper list_id (route 1); S→C sender session_ref (§ 6.10)
u16 reserved
```

**Header details (fixed in M4):** multi-byte fields are big-endian. `version` is the high nibble of the first byte and is 1; the flags are its low nibble: `EOT` = 0x1, `DTX` = 0x2, and 0x4 and 0x8 are sent as 0 and ignored on receipt, as is `reserved`. `seq` and `timestamp` are the sender's and wrap; the server passes them, `EOT`, `DTX`, `codec` and the payload through untouched, rewrites `ref`, and zeroes the flag bits 0x4 and 0x8 and `reserved` before forwarding, so a later meaning for them can only ever be set by the server. Client to server, `ref` is the sender's own `session_ref` (§ 6.10) on route 0 and a whisper `list_id` on route 1; server to client it is the sender's `session_ref` on either route, and `route` tells a whisper from channel audio.

**Validation:** the server drops, silently and before any work, a datagram that is shorter than 16 or longer than 1,200 bytes, has another `version`, a `codec` other than 1 or 2, `route` 2, a `key_id` other than 0, or arrives from a session not in voice; a route-0 datagram whose `ref` is not the sender's current `session_ref` (one sent before a move), a route-1 datagram naming no registered list, and one over the sending rate (§ 6.10) are dropped too. Drops are counted, never logged; the counters carry a reason only, never a session, account or address. Datagrams received before `Welcome` are discarded unread. Every QUIC connection's datagrams are read as they arrive, a member's out of voice and a non-member's alike (and dropped), and at most 64 KiB of them wait to be read, so none pile up unread.

**Payload size:** a datagram is at most 1,200 bytes and never more than the path's current maximum (`max_datagram_size`, which QUIC overhead keeps below 1,200 on a minimum-MTU path), so senders keep frames well below the cap, and frames are 20 ms or longer (§ 6.10 limits the datagram rate); a copy too large for one listener's path is dropped for that listener only. The bitrate is the client's: `max_bitrate` per channel (§ 6.8) is advice the server publishes and does not enforce, beyond the size cap, the datagram rate and, from M9, a byte rate per sending session (§ 6.10: 64,000 bytes a second of datagrams, bucket 64,000, enough for music on the channel and a whisper at once); 0 means the codec default, 64 kbit/s for voice and 128 kbit/s for music. At 20 ms, voice is at most 96 kbit/s and music at most 192 kbit/s; a channel's `max_bitrate` applies to whichever codec a speaker uses.

**Sending:** the server forwards with QUIC's unreliable datagram send, which drops the oldest queued datagram when the connection's `voice_send_buffer` is full; it never waits for a listener.

**Routing**
- Voice goes to every session in the speaker's channel that may hear it, minus the deafened.
- Whisper lists are registered beforehand and re-checked when permissions change.
- Talk power is checked when the routing table is built, never per packet (§ 6.10 has the full rules).
- Senders are identified per stream, so bots and clients get separate audio per person.

**When there's no voice path**
- If datagrams can't be negotiated, or UDP is blocked, there's no voice in 1.0. The client shows "voice blocked by network". Voice over TCP is P2.

### 6.5 Files

**Storage**
- Blobs are stored by sha256 and deduplicated per space. Garbage collection is a refcount sweep: blobs no attachment references are removed after 24 h.
- **Access is always by attachment ID, never by hash.** Each attachment belongs to one message or profile, and its visibility follows that channel's permissions.

**Quotas**
- Quotas count the logical size of each upload against the uploader and the space, even when the blob is shared.

**Downloads**
- Over a request stream, or a signed HTTPS URL. URLs are scoped to the attachment and expire after 10 min.

**Images**
- Thumbnails are made in a size- and time-limited worker.
- Avatars and space icons use the blob store from M2. Message attachments come in M3.

**Blob store core (M2)**
- A blob is a file at `blobs/<h0h1>/<h2…h63>` (its lowercase hex SHA-256, split after two characters), written to a temporary file in `blobs/` and renamed into place. The `blobs` row (§ 7.1) holds the hash, size and media type, never a file name. An `attachments` row gives the access id (`blob_id` on the wire) and points at one owner: a profile avatar or the space icon in M2.
- An upload belongs to the account that made it (`attachments.uploaded_by`): only that account can reference its `blob_id` in `set_avatar` or `set_space_icon`, and an attachment is referenced by one avatar or the icon at most. Replacing or clearing an avatar or the icon, and removing a member, deletes the old attachment row. An attachment no avatar or icon references, and a blob no attachment references, is deleted by the housekeeping sweep after 24 h.

**Avatar and icon intake (M2)**
- An upload is a `Request` kind `upload_image` (§ 6.8). Its request frame is at most 1 MiB on both transports, checked on the length prefix (§ 6.1), so the image is at most 1 MiB − 4 KiB (1,044,480 bytes); clients check before sending, and a larger image is `TOO_LARGE`. This replaces § 6.1's unidirectional file stream for images, so the TCP fallback can upload before HTTPS file URLs exist (M3). An account holds at most 5 uploads no avatar or icon references yet, counting uploads still being processed. The count is checked first: an upload that passes reserves a slot, and a sixth is `CONFLICT` and uses no token. An upload that fails afterwards (including `RATE_LIMITED` from the bucket below) frees its slot, and uploads take a token from a per-account bucket of 10 per minute; both fixed, not configurable in M2.
- Accepted: PNG, JPEG and WebP, by their magic bytes, not by any name or type the client gives. The header's dimensions are read before decoding: more than 4 megapixels (or any side over 8,192 px, or more than 16 MiB once decoded) is `INVALID`, and so is an animated WebP (only its first frame would be kept).
- The image is decoded and re-encoded to at most 512 × 512 px (aspect kept), as WebP, in a short-lived helper process: the server's own binary, `yapsta-server decode-image`, with no environment, `/` as its directory and no stderr. The image goes in on stdin; the WebP, or the index of a fixed refusal, comes back on stdout. Nothing the helper writes is echoed. On Linux the helper caps itself before reading: `RLIMIT_DATA` 64 MiB (its heap and private writable mappings, not its code, so the cap does not depend on the binary's size or the machine's core count) and `RLIMIT_CPU` 5 s. A decode the header cannot predict, such as a WebP whose Huffman groups take about 375 MiB from a 1 MB file, kills only the helper, and the upload is `INVALID`. Every legitimate fixture decodes in under 48 MiB. On other systems the cap is off and the server logs a warning at startup (§ 5).
- **Sandbox (Linux, #78):** after capping itself and before reading, the helper locks itself into a seccomp allow-list (`seccompiler`, with `PR_SET_NO_NEW_PRIVS`): `read` on fd 0, `write` on fds 1 and 2, memory calls that never map anything executable (`mmap` anonymous only; allocator advice only), plain futex waits and wakes, signals to its own process only, and exit. `decode-image` is internal: `run` starts it with stderr discarded. Any other call, or one of another ABI, kills it with `SIGSYS`, so an exploited decoder cannot open files, create sockets, exec, use an inherited fd or signal the server. A helper that cannot cap or sandbox itself exits without reading (code 4) and the server logs a warning; `run` starts one helper on nothing at startup so that shows before the first upload. A helper killed by a signal is logged with the signal only; `SIGSYS`, the sandbox stopping a call the helper makes (a new glibc or decoder), is logged apart, since every image then fails.
- One helper runs at a time, so two concurrent uploads stay within 80 MB. The slot is held by a task of its own until its helper is reaped, so neither the 5 s limit (past it the helper is killed and the request answered `INVALID`; the connection stays open) nor a closed connection frees it early. Re-encoding drops EXIF, GPS and every other metadata chunk and defeats polyglot files. Only the re-encoded image is stored. A re-encoded image over 1 MiB − 4 KiB is refused (`INVALID`), so every stored image fits one frame when fetched.
- **Custom emoji (M3):** `upload_image` with purpose `EMOJI` takes the same path and limits, re-encoded to at most 128 × 128 px instead of 512 × 512; it counts toward the same 5 pending uploads.

**Message attachments (M3)**
- An attachment is uploaded first and is **pending** until `send_message` takes it (§ 6.9). Every upload records its purpose (`avatar`, `emoji` or `file`, § 7.1), and each command takes only its own purpose. An account holds at most 10 pending file attachments, upload slots not yet completed included; an 11th is `CONFLICT` and uses no rate token. These are kept apart from the 5 pending image uploads above. A pending attachment unused after 24 h, and an upload slot whose URL has expired without a completed upload, are deleted by housekeeping, freeing their quota.
- **Two paths:** `upload_attachment` carries a file of at most 1 MiB − 4 KiB in its request frame (as `upload_image`). A larger file, or any file from a client that prefers it, takes `upload_url`: the server checks the size (1 byte to `max_attachment_bytes`), the pending limit, the quotas and the rate, creates the slot's attachment id and returns a signed `PUT` URL (below). Both take a token from `rate_upload_per_min`.
- **The stored file is the uploaded bytes**, unchanged and never decoded except for thumbnails: users expect the original back. Removing metadata such as EXIF is the client's job before upload (Yapsta Client does). No file name is stored or sent, ever (§ 7.1); clients name a saved file from the media type and the attachment id.
- **Media type** comes from the first bytes, from a fixed table (PNG, JPEG, WebP, GIF, PDF, ZIP, Ogg, MP3, MP4, WebM, WAV), and is `application/octet-stream` otherwise. What the client claims is never used.
- **Thumbnails:** a PNG, JPEG or static WebP within the avatar limits above (4 megapixels, 8,192 px a side, 16 MiB decoded) gets a thumbnail of at most 320 × 320 px WebP, made by the same `decode-image` helper and slot (one at a time, sandboxed); it is stored as its own blob, which the blob sweep counts as referenced through `attachments.thumbnail_sha256` like any attachment's file, and `width` and `height` are the original's. An image past those limits, an animated WebP, or one the helper refuses or that is killed is still stored, with `has_thumbnail = false`, so uploading never depends on the decoder. Thumbnails are made after the upload is stored and before its reply, so a message never shows an attachment whose thumbnail is still pending.
- **Quotas:** each attachment's size counts against its uploader (`quota_account_bytes`) and the space (`quota_space_bytes`) from upload until its row is deleted, even when the blob is shared (§ 6.5 above); 0 = no limit. An upload that would pass either is `CONFLICT` before anything is written; a URL upload is charged its declared size when the slot is created. From M9 `quota_space_bytes` defaults to 10 GiB, and an upload is also `CONFLICT` while the data directory's filesystem has less free space than `min_free_disk_bytes` (1 GiB), checked once when the upload or slot starts, off the tokio workers, so SQLite still has room to write (§ 6.16). Avatar and emoji uploads (`upload_image`) are checked against the same floor (#432), by the bytes as sent, before their slot or token, decided under the same free-disk admission as attachment uploads and upload slots (so an image upload can wait behind a slot's commit); the admission is let go at once, so images in flight can overshoot the floor by at most their count × 1 MiB. Images stay outside both quotas: at most 5 pending images per account, and images in use are bounded by what references them.
- **Downloads:** `fetch_attachment` returns the file, or its thumbnail, in one reply frame when the stored file is at most 1 MiB − 4 KiB; a larger one is `CONFLICT` (the connection stays open) and is fetched through `attachment_url`.

**HTTPS file listener (M3)**
- `https_listen` (default `[::]:7121`, `off` disables it) serves files over HTTPS: TLS 1.3 only, the server's certificate (§ 6.2), HTTP/1.1 and HTTP/2 by ALPN. It is the § 6.1 port 7121 listener; the admin API, metrics and the panel join it in M6 (§ 6.13). With it off, clients can move files only up to 1 MiB − 4 KiB, over requests.
- **Routes:** `GET /files/<attachment_id>?t=<0|1>&exp=<unix seconds>&sig=<signature>` (`t=1` = the thumbnail) and `PUT /uploads/<attachment_id>?exp=<unix seconds>&sig=<signature>`. Any other method or a malformed query on these paths is 404. Until M6 nothing else is served and every other path is 404; from M6 every other path goes to the admin service (§ 6.13), and is 404 when `admin_api` is off.
- **Signatures:** `sig` is the base64url (no padding) HMAC-SHA256, under the 32-byte key `secrets/url.key` (§ 5; created at `init`, 0600; replacing it invalidates every URL), of the fixed-width string `"yapsta-url-v1\0"` ‖ method (1 byte, `G` or `P`) ‖ `attachment_id` (u64 big-endian) ‖ thumbnail (1 byte, 0 or 1; 0 for `P`) ‖ `exp` (u64 big-endian). The server parses `t` as exactly `0` or `1` and `exp` as a decimal u64, rejects `exp` in the past or more than 600 s ahead, and compares the MAC in constant time. Any failure is 404, the same as a missing attachment, and is never logged with the URL.
- **Issuing:** `attachment_url` and `upload_url` return URLs that expire 10 min after issue. The URL is the path and query only, unless `public_https_base` is set (then it is prefixed with it, e.g. `https://chat.example.org`); a client otherwise uses `https://<the host it connected to>:7121`. A download URL is checked only against its signature and expiry, so access lasts at most until `exp` even if the requester loses access to the channel meanwhile; the attachment itself must still exist.
- **Uploads:** the `PUT` must carry `Content-Length` equal to the size bound to the slot when it was issued (not to anything in the URL), and the body is limited to that size while it streams (`413` past it, and the connection closes); a slot takes one upload at a time (a `PUT` while another is running for it, or after it completed, is 404). A `PUT` with no body bytes for 30 s is aborted. **Progress floor:** every upload and download body keeps a pace of at least 240 KiB per 60 s (4 KiB/s) from its start, with one window's worth (240 KiB) of slack: once it has moved 240 KiB less than that pace owes, it is cut. It is checked on a timer (and as a download body is polled), so a body that stops moving altogether is cut too, and the count is cumulative, so a client keeping the pace is never cut however bursty its reads; a body is never counted more than four windows ahead, so the first burst into the socket buffers buys a trickler at most that. An upload is answered `408` and the connection closes; a download ends its body (HTTP/1.1: the connection closes; HTTP/2: that stream is reset, the others go on, however busy). The tail is no exception: a body that stalls short of its end, a small file included, is cut once it is a window's worth behind the pace, so no body can be held open by not reading it. Clients retry a cut download with a new URL. The body streams to a temporary file in `blobs/` while it is hashed, then is stored as any blob, its media type sniffed and its thumbnail made (only for a file of at most 1 MiB − 4 KiB, the image helper's input: a larger image is stored with `has_thumbnail = false`); the reply is `201` with an empty body, and the attachment becomes pending. An interrupted or aborted upload deletes its temporary file and frees the slot for another `PUT` until the URL expires; temporary files left by a crash are deleted at startup.
- **Responses** carry `Content-Type` (the sniffed media type), `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox`, `Cache-Control: no-store` and `Referrer-Policy: no-referrer` (from M9 also `Strict-Transport-Security`, § 6.13), so a browser never renders a file in the server's origin.
- No request on this listener is logged with its path, query or address (so no default request-tracing layer, which logs the URI); logs carry the attachment id and status only.

### 6.6 Screen share and video (M7)

Screen share (with its audio) and camera go through a selective forwarding unit (SFU) in the server: a publisher sends one encrypted WebRTC stream to the server, and the server forwards it to each viewer without decoding it. Signalling (offers and answers, publish and subscribe) travels on the control stream, replacing Yapsta Client's peer-to-peer `plugincmd` chunking. Only sessions in voice share or watch, in their own voice channel: a share is part of the channel, like its voice. The exact messages and numbers are `yapsta.proto`; this section fixes them first, with § 6.8's conventions (`?` fields are `optional`; enum values are written short here, `MEDIA_KIND_SCREEN` in `yapsta.proto`).

**Objects**
```
enum MediaKind{UNSPECIFIED = 0, SCREEN = 1, CAMERA = 2}
MediaTrack{media_id: u64 = 1, account_id: u64 = 2, channel_id: u64 = 3, kind: MediaKind = 4}
TurnCredentials{urls: repeated string = 1, username: string = 2, password: string = 3, expires_at: u64 = 4}
enum MediaEndReason{UNSPECIFIED = 0, LEFT = 1, PERMISSION = 2, MODERATION = 3, FAILED = 4, TRACK_ENDED = 5}
```
- A **track** is one published stream: a screen (video, plus its audio when the publisher shares it) or a camera (video only; the voice channel carries the voice). `media_id` is a `u64` from one server-wide counter, starting at 1 and never reused while the process runs (as `session_ref`, § 6.10); it is not stored and means nothing across restarts.
- A **subscription** is one viewer's receiving of one track, named by a `subscription_id` from the same counter.
- `expires_at` is unix seconds.

**Commands** (`Command.kind`, continuing from 54; replies as § 6.8):

| # | Kind | Fields | Allowed for | Reply |
|---|---|---|---|---|
| 55 | `publish_media` | `kind: MediaKind`, `sdp_offer: string` | the session is in voice (§ 6.10) and is heard there (below); `SCREEN_SHARE` (screen) or `VIDEO` (camera) on its voice channel; `rate_media_per_min` | `CommandResult.media_published` |
| 56 | `unpublish_media` | `media_id` | the track's own session | `Ack` |
| 57 | `subscribe_media` | `media_id` | the session is in voice in the track's channel; `rate_media_per_min` | `CommandResult.media_offer` |
| 58 | `answer_media` | `subscription_id`, `sdp_answer: string` | the subscription's own session | `Ack` |
| 59 | `unsubscribe_media` | `subscription_id` | the subscription's own session | `Ack` |

```
PublishMedia{kind: MediaKind = 1, sdp_offer: string = 2}      UnpublishMedia{media_id: u64 = 1}
SubscribeMedia{media_id: u64 = 1}      AnswerMedia{subscription_id: u64 = 1, sdp_answer: string = 2}
UnsubscribeMedia{subscription_id: u64 = 1}
CommandResult gains: media_published: MediaPublished{media_id: u64 = 1, sdp_answer: string = 2} = 8,
                     media_offer: MediaOffer{subscription_id: u64 = 1, media_id: u64 = 2, sdp_offer: string = 3} = 9
```
- **Publishing:** the client offers (`sendonly`; one video m-line, plus one audio m-line for a screen with audio); the server answers. **Subscribing:** the server offers (`sendonly` from the server, with only the codecs the track carries) and the client answers with `answer_media` (`recvonly`); until then the subscription receives nothing, and one not answered within 30 s ends (`FAILED`). An answer refused `INVALID` for its length or because it does not parse (checked by the session task, before the media thread) leaves the subscription waiting for a valid one until its 30 s end. An answer the media thread rejects in negotiation (str0m consumes the pending offer) ends the subscription: the reply is `INVALID`, no `media_ended` follows, and the viewer subscribes again. `answer_media` after one was accepted is `CONFLICT`; from M9 that is decided before the SDP is parsed, and a repeat takes no other work. A test covers an invalid-then-valid answer of each kind.
- **ICE:** the server is ICE-lite. It puts all its candidates (UDP and TCP on the media port, below) in its SDP, never trickles, and learns each client's address from the client's connectivity checks, so there is no candidate message. From M9 a peer is **pinned** when the server sends it its first DTLS record, to that record's transport and address (a UDP address, or its ICE-TCP connection): from then on nothing from anywhere else reaches its `Rtc`, even a check with valid credentials, and nothing is sent anywhere else (a peer whose pinned address another pinned peer already holds fails at once, after that one record), so a forged nomination (ICE-lite checks no return route) cannot move its traffic, and only someone who received the server's first flight can finish the handshake. Addresses it learned before are forgotten, and an address another pinned peer uses is never taken over. **Client contract:** keep sending on the pair the server's first DTLS record arrived on; a pair the client switches to after it (a dual-stack client whose better pair answers late) is not served, and its ICE falls back to the pinned pair, which can delay the first frame by a few seconds. A client whose address changes (a NAT rebind, a network switch) loses the stream and subscribes or publishes again; the 30 s no-traffic end (below) tells it (§ 6.16). A client may leave its own candidates in its SDP (non-trickle, as Yapsta Client's peer-to-peer share does today); the server needs none. A viewer receives only the server's candidates, never a publisher's, so no viewer learns a publisher's address.
- **Bitrate (M9):** each live track has a token bucket on the media thread, refilled at `media_max_screen_kbps` (screen, its audio included) or `media_max_camera_kbps` (camera), holding 2 s of that rate. Each packet is charged its payload plus 52 bytes (RTP header, IP, UDP and SRTP), and never less than 200 bytes, since forwarding costs per packet as well as per byte. Packets over it are dropped before they are copied to viewers; a track over it for 5 s in a row (packets dropped in each of 5 consecutive one-second windows, counted from its start) ends with `FAILED`, as for any failure, and is counted as the `media_over_bitrate` refusal (§ 6.13). The server tells the publisher about once a second by REMB on its video stream the cap less room for a screen's audio (148.8 kbit/s, enough for 128 kbit/s Opus) and for the per-packet charge (× 1,148 / 1,200), then 90 % of that for each frame's partial last packet and an encoder's overshoot, so an encoder that honours REMB stays under the cap and the bucket stops only those that do not. The § 13 video profile (5 Mbit/s average, keyframe bursts every 2 s) stays under the screen cap (§ 6.16).
- **Ids:** `subscribe_media` with a `media_id` that is not a live track in the session's own voice channel is `NOT_FOUND`, whether it never existed, has ended, or is in another channel, seen or hidden (§ 6.8: missing and hidden are one answer). `unpublish_media` acts only on the session's own track, and `unsubscribe_media` and `answer_media` only on its own subscription, live or being set up; any other id (another session's, ended, never minted, 0, or of the other kind) is acknowledged and changes nothing, so these commands answer the same whatever exists, and one racing an end is not an error.

**Request** (`Request.kind`, continuing from 14): `turn_credentials: TurnCredentialsRequest{} = 15`, answered `Response.turn_credentials: TurnCredentials = 10`. `CONFLICT` with the fixed text "no TURN server" when none is configured (checked first), and "not in voice" for a session that is not in voice. `TurnCredentials` gets a hand-written redacting `Debug` (the password and the username).

**Events** (`Event.kind`, continuing from 26): `media_track_added: MediaTrackAdded{track: MediaTrack = 1} = 27` when a track goes live (its second apply step, below; the publisher may receive its own track's event before its `media_published` reply, and knows it by `account_id` and `kind`), and `media_track_removed: MediaTrackRemoved{media_id: u64 = 1} = 28` when it ends, each to every session that can see the track's channel. Persistent (§ 6.3): a replay brings them. **Ephemeral** (`Ephemeral.kind`, continuing from 6): `media_ended: MediaEnded{oneof target{media_id: u64 = 1; subscription_id: u64 = 2}, reason: MediaEndReason = 3} = 7`, to the owning session when the server ends its track or subscription; never when the session ended it itself, and never on a session that is closing. A `MediaEnded` without a `target` is ignored by clients. `media_track_removed` is published only for a track that was live (its `media_track_added` was published); a recorded `media_track_removed` keeps the track's channel beside it, server-side, so a replay filters it by channel like the live event. **Snapshot:** `Snapshot` adds `media_tracks: repeated MediaTrack = 13`, the live tracks in channels the session can see. A new connection, a resume included, has no tracks and no subscriptions of its own: media, like voice, ends with its session.

**Rules**
- **Check order.** `publish_media` and `subscribe_media` from a session that is not in voice are `CONFLICT` with the fixed text "not in voice", checked first: in voice, the session has passed the channel's `CONNECT`, password and `max_members` checks already. Then § 6.8's order: existence and visibility (`NOT_FOUND`, Ids above), permissions (`FORBIDDEN`), values (`INVALID`), state and limits (`CONFLICT`), the rate limit (`RATE_LIMITED`). An offer's values are checked by the session task before the core sees the command; an answer's (it needs the offer) by the media thread, which returns `INVALID` the same way.
- **Values.** An `sdp_offer` or `sdp_answer` longer than 16,384 bytes is `INVALID`, checked on its length before anything parses it. So is SDP that does not parse; an unspecified or unknown `kind`; a publish offer that does not match its `kind` (no video m-line, more than one video or audio m-line, audio on a camera, an `application` m-line, a direction other than `sendonly`); a subscriber's answer that accepts none of the offered codecs; a subscriber's answer that is not `recvonly`; and any SDP that is not DTLS-SRTP: a profile other than `UDP/TLS/RTP/SAVPF` (ICE-TCP candidates go with it too; the media thread's parser stops at any other m-line, so it never negotiates one), no `a=fingerprint`, or SDES `a=crypto` keys. Codecs: H.264 constrained baseline (`profile-level-id` `42e0xx` or `42c0xx`, any level) with `packetization-mode=1` (what Yapsta Client's hardware encoders send), VP8, and Opus for a screen's audio; an offer with none of the video codecs, or a screen audio line without Opus, is `INVALID`. The media thread's codec config lists exactly these (one H.264 entry, `42e01f` with `packetization-mode=1`, beside VP8 and Opus), so an offer's other H.264 payload types (High, Main, plain Baseline, mode 0) are left out of the answer and never reach a viewer (#269). str0m matches H.264 by packetization mode and profile class, level aside, so the answer also takes any `profile-level-id` it classes as constrained baseline (constraint_set1 on `42`, constraint_set0 on `4D`, both on `58`; all constrained-baseline bitstreams) and states it as `42e01f`.
- **Who may publish.** The session itself is in voice (so QUIC with datagrams: a TCP session cannot share in 1.0) and is heard there: `SPEAK`, enough talk power, not `server_mute`, no running timeout (§ 6.10 "Who is heard"); otherwise `FORBIDDEN`. `self_mute` mutes the microphone only and does not touch a share or its audio.
- **Who may watch.** A session in voice in the track's channel, so the channel's `CONNECT`, password and `max_members` already apply to every viewer, and every viewer is in the channel's voice states. A viewer's `self_deaf` or `server_deaf` drops the screen's audio for that viewer only (as voice, § 6.10), never its video; a change takes effect at the server within 100 ms.
- **Limits** (the last is configurable): one screen and one camera track per session (a second of the same kind is `CONFLICT`); at most 25 subscriptions per session and one per track (subscribing again to the same track is `CONFLICT`); at most 50 subscriptions per track; at most `media_max_publishers_per_channel` (default 10) accounts publishing in a channel at once (`CONFLICT` past it).
- **Rate.** `publish_media` and `subscribe_media` take a token from `rate_media_per_min` per account (default 60, bucket size = the rate), after every other check, and get it back when the command is then refused `UNAVAILABLE` (below); nothing else takes one. The bucket is its own, not `rate_voice_per_min`'s, so following a share across channels never runs out of voice joins.

**What ends media.** A live track or subscription ends in the apply step of the change that ends it (§ 4), before its events are published: the core removes it, publishes `media_track_removed` for a track, removes it from the media thread's snapshot (below), and sends `media_ended` with this reason, unless the session ended it itself. When one change ends a subscription for a cause of its own and also its track, the subscription gets its own reason; `TRACK_ENDED` only when its track is the only cause. A track or subscription still being set up (below) ends silently, and its command is answered `CONFLICT` instead:

| Cause | Ends | Reason |
|---|---|---|
| The publisher or viewer leaves voice: `leave_voice`, `join_voice` elsewhere, another of the account's sessions taking voice over | its tracks, its subscriptions | `LEFT` |
| Moved or disconnected by a moderator | its tracks, its subscriptions | `MODERATION` |
| `server_mute`, a timeout starting | its tracks | `MODERATION` |
| `SPEAK` or talk power lost; `SCREEN_SHARE` (screen) or `VIDEO` (camera) lost on the channel | the track | `PERMISSION` |
| `CONNECT` or `VIEW_CHANNEL` lost, the channel deleted (§ 6.10 eviction) | its tracks, its subscriptions | `PERMISSION` |
| The track a subscription receives ends | the subscription | `TRACK_ENDED` |
| No answer within 30 s; ICE or DTLS failure, a DTLS certificate that does not match the SDP fingerprint, or no traffic (STUN consent checks, RTP or RTCP) for 30 s; the session's media queue full | the track or subscription | `FAILED` |
| The session ends (close, idle timeout, `SESSION_REPLACED`, kick or ban with `MEMBER_REMOVED` (§ 6.12), shutdown) | everything it had (its viewers' subscriptions: `TRACK_ENDED`) | none sent to it |

A timeout that later expires lets the member publish again; it restarts nothing. The server sends no RTP for an ended track or subscription more than 100 ms after the apply step that ends it (the bound is on the server's own sending, measured at its socket; packets already on the network still arrive). A test checks the cutoff at the server's egress, independent of network delay.

**The SFU** (`crates/media`, str0m 0.25 with `default-features = false` and its RustCrypto DTLS backend; no OpenSSL; aws-lc only through that backend's DTLS crate, § 5).
- **One thread.** A named `std::thread` (`yapsta-media`) owns the media UDP socket, the ICE-TCP listener and every str0m `Rtc`; no media work runs on the tokio workers that carry voice and the control streams. It starts with `run`, binding both sockets (so a port in use fails `run` at once, as the other listeners do), and allocates nothing per peer until the first track, so an instance nobody shares on pays only for one parked thread. It takes its time from an injectable clock, so tests drive its timers without sleeping.
- **Who knows what.** The core owns the registry of tracks and subscriptions, as it owns voice (§ 6.10): limits, events, `Snapshot.media_tracks` and the ends above read it in the apply step. The media thread knows tracks and subscriptions by id only. The core publishes an **authorization snapshot**, swapped atomically (`arc-swap`, MIT OR Apache-2.0, added with the implementing ticket): every track and subscription, live or being set up, with its owner and whether a viewer may hear the screen's audio; the thread reads it on every loop turn (at least every 10 ms) and drops any `Rtc` no longer listed, so the core never waits for the thread and an end can never be lost on a full queue.
- **Publishing and subscribing.** The core checks the command in an apply step, **reserves** the id (counted against the limits; nothing is published and nothing sent to anyone) and lists it in the snapshot as being set up. The session then hands the SDP to the thread on the thread's bounded queue (1,024 entries; full: the reservation is released and the command is `UNAVAILABLE`). The thread builds an `Rtc` only for an id the snapshot still lists, and answers on the session's own bounded queue (64 entries) with `try_send`, never waiting for a session (a session whose queue is full loses its media, `FAILED`); for an id no longer listed it answers "gone". Before writing the command's reply, the session runs a second apply step that re-checks the rules and makes the track live (publishing `media_track_added`) or the subscription active; if the reservation ended meanwhile, or the re-check fails, the id ends silently and the reply is `CONFLICT` with the fixed text "media ended" instead of the SDP. The session task writes a media command's reply before any `media_ended` naming its id: an end that reaches the session while the reply is still being made (the track went live and was ended at once) is held until the reply is written, although the session otherwise sends ephemerals ahead of replies. So every `media_ended` a client receives names an id its own successful reply gave it; a deterministic test pauses between the second apply step and the reply. A track's media (its m-lines) is known from its accepted offer, so a subscribe right after the publish reply gets its offer before the publisher has connected (#266).
- **Ends the thread finds** (`FAILED`) go into a set shared with the core (a mutex and a wake-up), drained by the core in its next apply step; an id stays there until it has left the snapshot, so a report is never lost and the set never holds more than the ids in the snapshot.
- **Packets.** Incoming packets are matched to their `Rtc` through an index by ICE ufrag and then by remote address, never by asking each `Rtc` in turn. Single layer, no simulcast (P2): each publisher's RTP is forwarded to each subscriber as it arrives, payload never decoded. Keyframe requests (PLI, FIR) from subscribers are coalesced per publisher: a request outside any window is forwarded at once and opens a 500 ms window; requests inside it (up to, not including, 500 ms) are merged into one, sent when it closes, which opens the next window (at the same instant, the window closes before a new request is handled); a merge that holds a FIR sends a FIR, otherwise a PLI. A subscriber that cannot keep up (an ICE-TCP viewer that stops reading) loses packets from its own send queue, at most 256 KiB; it never slows the publisher or the other subscribers. Dropping an `Rtc` discards its send queue and closes its ICE-TCP connection at once (no linger), so the 100 ms cutoff holds on TCP too.
- **Encryption.** Each hop is DTLS-SRTP (publisher to server, server to each subscriber), DTLS 1.2 with ECDHE and AEAD suites only, SRTP profiles `AEAD_AES_256_GCM`, `AEAD_AES_128_GCM` or `AES_CM_128_HMAC_SHA1_80` (str0m's set; DTLS 1.2 is set explicitly); there is no plaintext RTP or RTCP. The DTLS fingerprints travel only in the SDP, over the authenticated control stream (TLS 1.3, § 6.2), and a certificate that does not match ends the track or subscription. The server decrypts SRTP to forward it but never decodes, records or stores media. Media end-to-end encryption (SFrame) is after 1.0 (§ 7.7, § 12).
- **ICE-TCP** on the media port (TCP 7122, RFC 6544 passive candidates) serves networks that block UDP on QUIC sessions that still have datagrams (UDP allowed on 7120 but not 7122, or a strict NAT); `media_tcp_listen = off` disables it. At most 256 ICE-TCP connections in all and 8 per address key (§ 5), of which at most 64 not yet bound to an `Rtc`; addresses stay in the limiter's in-memory window only. An unbound connection is closed at once when it sends anything but a STUN binding request naming a known `Rtc`'s ufrag; after 2 s when no `Rtc` has accepted a check on it (str0m's `accepts`, which also takes anything from the address the `Rtc`'s UDP path nominated: the connection is then *proposed*); and after 10 s when no `Rtc` has bound it by answering a check it verified. When the 64 unbound places, or all 256, are full, a newcomer (within its address key's cap) closes the oldest unproposed connection of the address key holding the most of them (on a tie, the oldest of those keys' connections; proposed and bound connections are never closed for room); with none to close, the newcomer is refused. So silent connections cannot lock a client with the SDP out unless they come from more than 64 address keys, each reconnecting within 2 s (#271). An `Rtc` takes checks on at most 4 ICE-TCP connections (bound or proposed to it; enough for a dual-stack or multi-homed client): a check on one more never reaches the `Rtc`, so no pair or nomination comes of it, and that connection goes at 2 s. No connection is closed to make room: the client nominates, and the server cannot tell which bound connection carries the selected pair (#273). Once the `Rtc` is pinned (above), only its pinned path reaches it: a check on any other connection, or from the address its UDP path nominated, is dropped, so the 4 places and proposals matter only before the handshake (M9). A bound connection has no deadline, but every admitted connection has TCP keepalive (idle 30 s, then a probe every 10 s, 3 probes) and a 60 s user timeout (data unacknowledged for 60 s fails it; keepalive never probes a connection with data in flight, such as the one that carried media when its client left), both set per socket, not from host settings. So one left half-open (a client that changed networks without the server seeing a close) fails and gives up its place about 60 s after its last segment, idle or not (#276; the media stats count bound connections closed by a socket error). Within that window a client that moves more often than it has free places (more than three moves for a client with one connection, more than one for a dual-stack client with two, any for one already using all 4) still has its new checks dropped until a place frees or the `Rtc` fails for silence (30 s) and it subscribes again. Checks are not fresh (STUN short-term credentials, no replay protection), so someone on the path who captured one of a client's checks can replay it on 4 connections and fill that `Rtc`'s places; the client's recovery is a new subscription (new credentials). The same observer could already replay a nominating check or drop the client's packets. One session can own up to 27 `Rtc`s, so holding many of the 256 places still takes many address keys (8 per key). **Client contract:** open the ICE-TCP connection once the remote SDP is in hand and send the first binding request at once; a connection opened before signalling completes may be closed at 2 s. Use at most 4 ICE-TCP connections per `Rtc`.
- **Shutdown.** On stop the sessions close (`UNAVAILABLE`, § 6.1), which ends their media; the thread then exits within 2 s, and `run` waits for it as for the other listeners.

**NAT and TURN**
- **Advertised address.** The server's candidates carry `media_public_ip` when set. Otherwise a listen address that is not a wildcard is used as it is, and a wildcard bind (the default `[::]`) is resolved at startup to the host's interface addresses that are neither loopback, link-local nor unspecified, preferring globally routable ones: private, CGNAT and bridge addresses are advertised only when no global one exists, and then `run` logs a warning (without addresses) recommending `media_public_ip`. With none at all, `run` logs a warning and media stays off (as `media = off`). In a container or behind NAT the interface addresses are not the ones clients reach: the operator sets `media_public_ip` (with 7122 forwarded, UDP and TCP), or no media connects. A test covers the default wildcard bind.
- **TURN** is external, for clients that cannot reach the media port directly (str0m has no TURN client, and the server needs none as ICE-lite; built-in TURN is P2). `turn_urls` and `turn_secret` are set together or not at all (one without the other: `run` refuses to start). `turn_credentials` returns coturn's REST credentials: username `<expires_at>:<16 random bytes, lowercase hex>`, `expires_at` = now + `turn_ttl_secs` in unix seconds, password = standard base64 (padded) of HMAC-SHA1(`turn_secret`, username), so the TURN server's logs never name an account. The secret never leaves the server. Credentials stay valid until they expire, a kick or ban included; operators should restrict their TURN server's peers to the media address, so it cannot relay into their network: in coturn an `allowed-peer-ip` alone denies nothing, so deny every address of both families (`denied-peer-ip=0.0.0.0-255.255.255.255` and `denied-peer-ip=::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff`) and allow only the media address (`allowed-peer-ip`), or enforce the same with an egress firewall; `allowed-peer-ip` opens every port of that address, so a firewall that allows only UDP and TCP 7122 on each advertised address is tighter. The self-hosting guide (`docs/SELF-HOSTING.md`) shows this setup.

**Privacy and logs** (§ 7.6). No SDP, ICE candidate, IP address or port, ufrag, DTLS fingerprint, TURN credential or media payload appears in a log line, an `Error.message`, the database or a metric label; the media thread's metrics count tracks, subscriptions, packets, bytes and drops by kind and reason only. Media libraries never log: the `yapsta-media` thread's log filter is an allowlist of the server's own targets, whatever `log` says, so str0m and every crate it uses for ICE, DTLS, SRTP and SDP (its ICE agent is the separate `is` crate, whose lines carry ICE credentials and addresses), a new dependency included, are silent. The media thread logs its own content-free lines instead. A test runs a publish and a subscribe with `log=trace` and asserts that the captured output holds none of the run's actual values: its addresses and ports (IPv4 and IPv6 forms), ufrags and ICE passwords, and no `a=`, `c=` or `candidate:` line. `PublishMedia`, `AnswerMedia`, `MediaPublished`, `MediaOffer` and `TurnCredentials` get a hand-written `Debug` that prints the SDP's length only (and nothing of the credentials), and are listed in `crates/proto`'s redaction check. Nothing about media is stored: tracks and subscriptions live in memory and end with their session or a restart.

### 6.7 Versioning

- `yapsta-proto` (this repository) is the single source of the wire format.
- **From M1 on, everything in § 6 is stable API and changes add-only:** messages, field numbers and types, enum values, error and close codes, signed-byte-string prefixes, exporter label, ALPN.
  - Never renumbered, retyped or repurposed.
  - Never moved into or out of a `oneof`.
  - Retired numbers and names are `reserved`.
  - Every enum's 0 is `*_UNSPECIFIED`.
  - Relays forward received bytes and never decode and re-encode them, because prost drops unknown fields.
- Fields are only ever added. Capability flags (§ 6.2) announce optional features.
- **Version = ALPN major + minor.** The major is in the ALPN (`yapsta/1`). The minor is a `u32` starting at 1 (M1); 0 is invalid.
  - A minor adds surface; it never changes existing meaning.
  - `Hello.versions` lists the server's current and previous minors, and `Auth.version` picks one (§ 6.2).
  - To a client on the previous minor, the server sends nothing that minor cannot ignore.
  - A breaking change means a new ALPN major version.
- **Minors so far:** 1 = M1. 2 = M2 (§ 6.2 `Redeem`, § 6.3 events and snapshot, § 6.8). An M2 server sends `Hello.versions = [2, 1]` and accepts either. To a session on minor 1 it sends the M1 surface plus only frames a minor-1 client ignores (unknown bodies, event kinds and fields), and it answers minor-2 bodies from such a session with `INVALID`. Such a client can still authenticate, see presence and receive `MemberJoined`; it cannot redeem or manage.
  3 = M3 (§ 6.9, the M3 parts of § 6.3 and § 6.5). An M3 server sends `Hello.versions = [3, 2]`, so a minor-1 client gets `UNSUPPORTED_VERSION`. M3 adds kinds inside the existing `Command` and `Request` oneofs, so the gate works per kind: a minor-2 session that sends an M3 kind (or `start_typing`, answered only when `request_id` ≠ 0) gets `INVALID`. To a minor-2 session the server sends M2 frames plus only what a minor-2 client ignores (event kinds 14–25, ephemerals 3–5, the new `Snapshot`, `Resumed` and `Channel` fields).
  4 = M4 (§ 6.10, the M4 parts of § 6.3 and § 6.4). An M4 server sends `Hello.versions = [4, 3]`, so a minor-2 client gets `UNSUPPORTED_VERSION`. The gate works per kind as in M3: a minor-3 session that sends an M4 command, or `create_channel` with `temporary`, gets `INVALID`. To a minor-3 session the server sends M3 frames plus only what a minor-3 client ignores (event kind 26, ephemeral 6, `Snapshot` field 12, `Channel.temporary`); such a session cannot join voice, so it is never sent a datagram, and datagrams from it are dropped.
  5 = M5 (§ 6.11, the M5 parts of § 6.3 and § 6.9). From here minors no longer match milestone numbers: a later milestone takes the next minor. An M5 server sends `Hello.versions = [5, 4]`, so a minor-3 client gets `UNSUPPORTED_VERSION`. A minor-4 session that sends `apply_template`, or `update_space` with any field 4–10, gets `INVALID`. To a minor-4 session the server sends M4 frames plus only what a minor-4 client ignores (the new `Space` and `SpacePublicInfo` fields), and none of the chat of voice channels, whose meaning would be new to it (§ 6.11); it is never joined to a lobby.
  6 = M6 (§ 6.12, § 6.13). An M6 server sends `Hello.versions = [6, 5]`, so a minor-4 client gets `UNSUPPORTED_VERSION`. A minor-5 session that sends commands 51–54 or requests 13–14 gets `INVALID`. To a minor-5 session the server sends M5 frames plus only what a minor-5 client ignores (`Member.timeout_until`, `MemberRemoved.reason`); a kicked or banned minor-5 session is closed with `MEMBER_REMOVED` as before.
  7 = M7 (§ 6.14, § 6.6). An M7 server sends `Hello.versions = [7, 6]`, so a minor-5 client gets `UNSUPPORTED_VERSION`. The gate works per kind as before: a minor-6 session that sends `Redeem{open_join}`, `update_space` with field 11 or 12, commands 55–59 or request 15 gets `INVALID`. To a minor-6 session the server sends M6 frames plus only what a minor-6 client ignores (`Space` fields 13–14, `SpacePublicInfo.join_policy`, which `Hello` carries to every connection before a minor is chosen); it is sent no media events (27–28), ephemerals (7) or `Snapshot.media_tracks`, since it can neither watch nor be told why a share ended.
  8 = M8 (§ 6.15). An M8 server sends `Hello.versions = [8, 7]`, so a minor-6 client gets `UNSUPPORTED_VERSION`. A bot credential needs minor 8 (`UNAUTHENTICATED` on minor 7). The gate works per kind and per field as before: a minor-7 session that sends commands 60–66, requests 16–18 or `SetVoiceState.receiving_audio` gets `INVALID`. To a minor-7 session the server sends M7 frames plus only what a minor-7 client ignores (`Member.bot`, `VoiceState.receiving_audio`, `Message.webhook_id` and `webhook_name`); it is sent no `commands_updated` (event 29) and no `interaction` (ephemeral 8, which goes only to bot sessions, all minor 8). The one change of what it sees: a webhook's message reaches it as one with `author_id` 0, which a minor-7 client shows as a deleted member's (§ 6.15).
  9 = M9 (§ 6.16). An M9 server sends `Hello.versions = [9, 8]`, so a minor-7 client gets `UNSUPPORTED_VERSION`. A minor-8 session that sends `delete_thread` (command 67) gets `INVALID`. To a minor-8 session the server sends M8 frames plus only what a minor-8 client ignores (`AuditAction` values 22–37 in an `audit_page`, which it shows as an unknown action); it is sent no `thread_deleted` (event 30): a thread deleted while it is connected stays in its view until its next snapshot, and its requests for that thread's messages find none. The M9 refusals on existing commands (§ 6.16) reach every minor as ordinary `Error` replies with existing codes, so a minor-8 client needs no change to survive them; a minor-8 Yapsta Client or Yapsta Bot keeps working.
  10 = M10 (§ 6.17, the M10 parts of § 6.3; § 6.18 adds notification settings and push to this minor). An M10 server sends `Hello.versions = [10, 9]`, so a minor-8 client gets `UNSUPPORTED_VERSION`. The gate works per kind and per field as before: a minor-9 session that sends commands 68–81 or requests 19–20 gets `INVALID`, and its `StartTyping` with `dm_id` is dropped, as any typing the server does not forward (typing is never answered, § 6.9); `Resume.personal_last_seq` from an `Auth` that picks minor 9 is ignored. § 6.18 adds commands 82–85, `Welcome` field 8, personal event 11, `PersonalSnapshot` field 5 and `Capability.PUSH = 1`; a minor-9 session gets `INVALID` for 82–85, is never sent `Welcome.push_info`, and `PUSH` from it is ignored (it cannot register). To a minor-9 session the server sends M9 frames only: no `personal` or `personal_snapshot` body (19–20), no `Response.dms`, and no `Message` or `Typing` with `dm_id`. Bodies 19–20 are sent only by a server: a client of any minor that sends one is refused from its tag (§ 6.16). A minor-9 member can still be DMed: the messages wait in the DM, its read state stays at its last mark, and its minor-10 devices see them. Channel read states reach every minor unchanged (§ 6.9).

### 6.8 Community management (M2)

The space is managed through the protocol (§ 3.8), by `yapsta-cli` and Yapsta Client alike. The exact messages and numbers are `yapsta.proto`; this section fixes them first.

**Objects**
```
Space{owner_account_id: u64 = 1, name = 2, description = 3, rules = 4, icon_id: optional u64 = 5}   (M5 adds 6–12, § 6.11; M7 13–14, § 6.14)
enum ChannelKind{UNSPECIFIED = 0, CATEGORY = 1, TEXT = 2, VOICE = 3}
Channel{id: u64 = 1, kind = 2, parent_id: optional u64 = 3, position: u32 = 4, name = 5, topic = 6,
        slowmode_secs: u32 = 7, max_members: u32 = 8, has_password: bool = 9, age_restricted: bool = 10,
        needed_talk_power: u32 = 11, max_bitrate: u32 = 12, overwrites: repeated Overwrite = 13}
Role{id: u64 = 1, name = 2, color: u32 = 3, position: u32 = 4, hoist: bool = 5,
     permissions: fixed64 = 6, talk_power: u32 = 7}
Overwrite{channel_id: u64 = 1, oneof target{role_id: u64 = 2; account_id: u64 = 3},
          allow: fixed64 = 4, deny: fixed64 = 5}
Member{account_id = 1, joined_at = 2 (M1), nickname: optional string = 3, role_ids: repeated u64 = 4,
       display_name = 5, avatar_id: optional u64 = 6, bio = 7, pronouns = 8}   (M6 adds 9, § 6.12)
Invite{id: u64 = 1, created_by: u64 = 2, created_at: u64 = 3, expires_at: optional u64 = 4,
       max_uses: optional u32 = 5, uses: u32 = 6, role_ids: repeated u64 = 7}
BlobData{blob_id: u64 = 1, media_type = 2, data: bytes = 3}
```
- Unmarked fields are `string`; `u64`/`u32` are protobuf `uint64`/`uint32`. Ids are `u64`; positions, counts, seconds, colours and powers are `u32`; permission sets are `fixed64`; times are unix seconds (`u64`). `Space.owner_account_id` 0 = no owner (ids start at 1). `max_members` 0 = no limit; `max_bitrate` in bit/s, 0 = the codec default (§ 6.4); `color` is `0xRRGGBB`, 0 = none.
- **Snapshot form:** `Channel` without `topic`; `Member` without `bio` and `pronouns`; `Space` without `description` and `rules`. It is used by the snapshot and `member_page`; events and `get_*` carry the full form, and `SpacePublicInfo` carries `description` and `rules` too.
- `Member.role_ids` never lists `@everyone`; a member has at most 50 roles. `Channel.overwrites` is empty outside the snapshot and `get_channel`; overwrite changes travel as `overwrite_*` events.
- **Tree:** a `CATEGORY` has no parent. A `TEXT` or `VOICE` channel's parent is none or a category; a `VOICE` channel may also have a `VOICE` parent (a nested voice subchannel). Depth is at most 8 (a top-level channel is depth 1). `position` orders siblings from 0; the server renumbers siblings densely on every create, move and delete. Moving a channel under itself or one of its descendants, or so that it or its subtree would pass depth 8, is `INVALID`.
- **Roles:** `@everyone` is the role with id 1 and position 0, created with the space; it cannot be renamed, moved or deleted, and its overwrite is the role overwrite with `role_id = 1`. Higher `position` ranks higher (§ 8.1). The owner holds no special role; ownership is `Space.owner_account_id`.
- **A new space** (created by the M2 migration, or by `init`) is named `Yapsta`, has no owner (`claimed = false` until the claim code is redeemed), no channels, and only `@everyone`, which starts with `VIEW_CHANNEL`, `CHANGE_NICKNAME`, `SEND_MESSAGES`, `SEND_IN_THREADS`, `CREATE_THREADS`, `READ_HISTORY`, `ATTACH_FILES`, `ADD_REACTIONS`, `USE_CUSTOM_EMOJI`, `POKE`, `USE_COMMANDS`, `CONNECT`, `SPEAK`, `VIDEO`, `SCREEN_SHARE`, `WHISPER` and `USE_VOICE_ACTIVITY`. Inviting is the owner's until a role grants `CREATE_INVITES` (new instances are invite-only, § 6.2; from M7 `join_policy` starts as `INVITE_ONLY`, § 6.14). M1 databases have members from the test fixture only, and they keep no owner.

**Commands** (`Command` on the control stream, `request_id ≠ 0`, answered with `Ack`, a `CommandResult` or an `Error`; `oneof kind`, each message named after its kind in CamelCase). Update commands are patches: every settable field is `optional`, an absent field stays as it is, and nothing ever sends a whole object back (prost drops unknown fields, so a re-sent object would erase newer ones).

**Numbering.** Each command's and request's message has the fields of its row, numbered from 1 in the order listed, with the types above (`kind` is `ChannelKind`, `password` and `data` are `string` and `bytes`, `?` marks `optional`, `role_ids` is `repeated`). A `oneof target` is `{role_id = n; account_id = n + 1}` at the next numbers. Wrapper oneof numbers are the `#` columns. Request messages are named `MemberPageRequest`, `FetchBlobRequest` and `UploadImageRequest`; their replies `MemberPage`, `BlobData` and `Uploaded`.

| # | Kind | Fields | Allowed for | Reply |
|---|---|---|---|---|
| 1 | `get_space` | — | members | `space` |
| 2 | `update_space` | `name?`, `description?`, `rules?` (M5 adds the style and switches, § 6.11; M7 `join_policy?` and `open_join_role_ids?`, § 6.14) | `MANAGE_SPACE`; from M7 also `CREATE_INVITES` to open the space or set its roles (§ 6.14) | `Ack` |
| 3 | `set_space_icon` | `blob_id?` (absent clears) | `MANAGE_SPACE` | `Ack` |
| 4 | `fetch_space_icon` | — | anyone, also non-members (once per connection; again: `RATE_LIMITED`) | `blob`, or `NOT_FOUND`; one shared buffer for every reply |
| 5 | `create_channel` | `kind`, `parent_id?`, `position?`, `name`, `topic?`, `slowmode_secs?`, `max_members?`, `age_restricted?`, `needed_talk_power?`, `max_bitrate?` | `MANAGE_CHANNELS` (on the parent, if any) | `created_id` |
| 6 | `update_channel` | `channel_id`, `name?`, `topic?`, `slowmode_secs?`, `max_members?`, `age_restricted?`, `needed_talk_power?`, `max_bitrate?` | `MANAGE_CHANNELS` on it | `Ack` |
| 7 | `move_channel` | `channel_id`, `parent_id?` (absent = top level), `position` | `MANAGE_CHANNELS` on it and on the new parent | `Ack` |
| 8 | `delete_channel` | `channel_id` | `MANAGE_CHANNELS` on it | `Ack`; `CONFLICT` while it has children |
| 9 | `set_channel_password` | `channel_id`, `password?` (absent clears) | `MANAGE_CHANNELS` on it | `Ack` |
| 10 | `get_channel` | `channel_id` | `VIEW_CHANNEL` on it | `channel` (full, with overwrites) |
| 11 | `create_role` | `name`, `color?`, `hoist?`, `permissions?`, `talk_power?` | `MANAGE_ROLES` | `created_id`; placed directly below the actor's highest role (the owner's: at the top) |
| 12 | `update_role` | `role_id`, `name?`, `color?`, `hoist?`, `permissions?`, `talk_power?` | `MANAGE_ROLES`, role below the actor's highest | `Ack` |
| 13 | `move_role` | `role_id`, `position` | as 12, and the new position below the actor's highest | `Ack` |
| 14 | `delete_role` | `role_id` | as 12 | `Ack` |
| 15 | `add_member_role` | `account_id`, `role_id` | `MANAGE_ROLES`, role below the actor's highest, and the member ranked below the actor (or the actor themself) | `Ack` |
| 16 | `remove_member_role` | `account_id`, `role_id` | as 15 | `Ack` |
| 17 | `set_overwrite` | `overwrite: Overwrite` | `MANAGE_ROLES` on the channel; a role target below the actor's highest; a member target ranked below the actor | `Ack` |
| 18 | `delete_overwrite` | `channel_id`, `oneof target` | as 17 | `Ack` |
| 19 | `get_member` | `account_id` | members | `member` (full) |
| 20 | `update_profile` | `display_name?`, `bio?`, `pronouns?` | the member themself | `Ack` |
| 21 | `set_avatar` | `blob_id?` (absent clears) | the member themself | `Ack` |
| 22 | `set_nickname` | `account_id`, `nickname?` (absent clears) | own: `CHANGE_NICKNAME`; another's: `MANAGE_NICKNAMES` and the target ranked below the actor | `Ack` |
| 23 | `create_invite` | `expires_in_secs?`, `max_uses?`, `role_ids` | `CREATE_INVITES`; each role below the actor's highest; `rate_invite_create_per_min` | `invite_created{invite, code}` |
| 24 | `list_invites` | — | `MANAGE_INVITES` | `invites{repeated Invite}` |
| 25 | `revoke_invite` | `invite_id` | `MANAGE_INVITES`, or its creator; from M9 an id that does not exist and one the actor may not revoke (working or not) get the same `NOT_FOUND`, checked before whether it still works (§ 6.16) | `Ack` |
| 26 | `transfer_member` | `from_account_id`, `to_account_id` | the owner only | `Ack` |
| 27 | `transfer_ownership` | `to_account_id` | the owner only | `Ack` |

`CommandResult.kind`: `space: Space = 1`, `channel: Channel = 2`, `created_id: u64 = 3`, `member: Member = 4`, `invite_created: InviteCreated{invite = 1, code = 2} = 5`, `invites: InviteList{repeated Invite invites = 1} = 6`, `blob: BlobData = 7`.

**Requests** (`Request` on a QUIC request stream, or multiplexed on TCP, § 6.1; members only):

| # | Kind | Fields | Reply (`Response.kind`) |
|---|---|---|---|
| 1 | `member_page` | `after_account_id?`, `limit` (1–1,000) | `member_page{members: repeated Member = 1, has_more: bool = 2, presences: repeated PresenceUpdate = 3}` = 1: members in snapshot form by ascending `account_id`, online and offline, with the presence of the online ones |
| 2 | `fetch_blob` | `blob_id` | `blob: BlobData` = 2; `NOT_FOUND` unless it is the icon, an avatar of a member, or (M3) a custom emoji's image |
| 3 | `upload_image` | `data: bytes` | `uploaded{blob_id = 1}` = 3 (§ 6.5) |

**Rules for every command and request**
- Checks run in this order: the object exists and is visible to the actor (else `NOT_FOUND`, the same reply as a missing id, § 6.1), then the permission and hierarchy (else `FORBIDDEN`), then the values (else `INVALID`), then the state (else `CONFLICT`).
- **The owner** passes every permission and hierarchy check (§ 8.1). `ADMINISTRATOR` passes every permission check but not the hierarchy, and never the owner-only commands 26 and 27.
- **Hierarchy:** a member's rank is the position of their highest role (`@everyone` = 0); the owner, as a target, ranks above everyone. "Below the actor" means strictly lower. A member never grants a permission they do not hold themselves: the permissions a role gives are checked against the actor's base permissions (all of them on `create_role` and on `add_member_role`, the bits an edit adds on `update_role`). An overwrite is checked on its channel: `set_overwrite` needs the actor to hold there every bit whose allow or deny state the change touches, added or removed (lifting a deny could hand back what the channel takes from the actor; bits left as they were may stay), and `delete_overwrite` every bit in the existing allow and deny. One stated exception: taking a role ranked below the actor off oneself or off a member ranked below the actor (`remove_member_role`), or deleting such a role (`delete_role`), still needs `MANAGE_ROLES` and the hierarchy, but the role's permissions and overwrites are not checked against the actor's, even when an overwrite on that role denies its holders something on a channel where the actor lacks it. It only takes a role away, adding no allow and no base permission, so the rule does not apply (as in Discord). From M9 talk power follows the same rule: a role's `talk_power` set by `create_role` or `update_role`, and the role given by `add_member_role`, is at most the actor's own talk power (§ 8.2, the highest of their roles'), otherwise `FORBIDDEN`; the owner is not limited. As with permissions, `update_role` checks only a raise: lowering a role's talk power, or leaving it, is never refused for this. The same ceiling is part of "a role the creator could give" for invites and open join: `create_invite` refuses such a role (`FORBIDDEN`), and a redemption or open join skips a role whose talk power exceeds its creator's or setter's at that moment, as it skips other roles they could no longer give (§ 6.14).
- **Text** is UTF-8 data, never markup, and is bounded in bytes: space `name` 64, `description` 1,024, `rules` 4,096; channel and role `name` 1–32 (not blank, no `/` in channel names, so a bot's channel path stays unambiguous); `topic` 1,024; `display_name` and `nickname` 1–32; `bio` 190; `pronouns` 40; channel `password` 1–64. Names (space, channel, role, display name, nickname; from M9 also thread names and poke text, § 6.9) contain no control (`Cc`) or format (`Cf`, e.g. the bidi controls U+202A–U+202E and U+2066–U+2069) characters, except U+200D (zero-width joiner, for emoji sequences) and, from M9, the tag characters of a flag's tag sequence (below). From M9 they also contain no line or paragraph separator (U+2028, U+2029) and no default-ignorable code point (Unicode `Default_Ignorable_Code_Point`, e.g. U+200B, U+2060, U+3164, U+FFA0) except inside an emoji: the variation selectors U+FE0E and U+FE0F right after a character that is not whitespace, U+200D or another variation selector, U+200D only between two `Extended_Pictographic` characters (each optionally followed by U+FE0F or a skin-tone modifier), and the tag characters U+E0020–U+E007F only in a tag sequence that follows U+1F3F4 and ends with U+E007F (a subdivision flag). A stored name the stricter rule would refuse stays as it is and is still sent; only new writes are checked (§ 6.16). Over a bound or a refused character is `INVALID`. Names need not be unique, and the server makes no look-alike check. Free text (`description`, `rules`, `topic`, `bio`, `pronouns`) may hold any characters, control and format ones included; clients render it as data and neutralise such characters themselves.
- **Limits:** 500 channels, 250 roles (with `@everyone`), 5,000 overwrites and 1,000 active invites (unexpired, unrevoked, not used up) per space; `list_invites` returns the active ones only, so it fits one frame; 50 roles per member (`add_member_role`, an invite's `role_ids`, and a transfer whose combined roles would pass it are refused with `CONFLICT`); `slowmode_secs` ≤ 21,600 (text channels, and voice channels from M5); `max_members` ≤ 99 (voice channels); `needed_talk_power` and `talk_power` ≤ 1,000,000; `max_bitrate` within § 6.4; an invite's `max_uses` 1–1,000 and `expires_in_secs` 60–2,592,000 (30 days; absent = never). Over a limit is `INVALID` (a count limit: `CONFLICT`).
- **Effects:** every successful change is validated, committed, applied and published (§ 4) as the § 6.3 events, and live sessions whose view changed get `resync`.
- **Channel passwords** are secrets: hashed with argon2id off the tokio workers (the claim code's pool, § 6.2), stored only as the hash, never sent (only `has_password` is), never logged, never in `Debug` or `Error.message`. They are checked when joining voice (M4).
- **Secrets in messages:** `Redeem`, `SetChannelPassword` and `InviteCreated` get a hand-written redacting `Debug` (prost-build `skip_debug`), as M1's secret-bearing messages do, so printing an `Envelope` never shows a code or password.
- **Invites:** `create_invite` returns the code once; it is 16 bytes from the OS RNG in lowercase RFC 4648 base32 without padding (26 characters), shown as `yapsta://host[:port]/invite/<code>`, and stored only as the SHA-256 of that text (§ 7.6); a redeemed code is lowercased first, so one typed in capitals still works. An invite is used up at `max_uses`, expires at `expires_at`, and stops working when revoked; housekeeping deletes it, with its roles, 7 days after the first of these (§ 7.2), so `revoke_invite` on it is `NOT_FOUND` from then. An invite whose creator lost the right to give it (below) is not deleted: it works again if the creator regains it. Redeeming one creates the membership with the invite's roles in one transaction with the use count (§ 6.2). The roles are checked against the creator when the invite is redeemed: roles deleted since, or that the creator could no longer give, are skipped, and an invite does not work while its creator is not a member or does not hold `CREATE_INVITES`. `revoke_invite` on an invite that no longer works is acknowledged.
- **Member transfer** (account recovery, § 6.2): `from` and `to` are two different members (the same account twice is `INVALID`; `to` normally joined through an invite with its new identity), and neither is the owner (the owner transfers ownership first). In one transaction the server gives `to` the roles of `from` (added to its own; a role both hold counts once toward the 50) and the nickname of `from` (only when `from` has one: otherwise `to` keeps its own), bans `from` (§ 7.1), removes its membership and its avatar's attachment (from M8 also the webhooks `from` created, § 6.15), and writes an audit entry. Then it closes the sessions of `from` with `MEMBER_REMOVED`, drops its resume tokens, and publishes `member_updated` and `member_removed`. Invites `from` created stop working, as for any creator who is not a member (above). Channel overwrites naming `from` are not moved to `to`: from M9 they lose their grants with its membership, as at every removal (§ 6.12). Bots `from` created keep their keys (the same person holds the seeds), and from M9 their `created_by` becomes `to` in the same transaction, so a later removal of `to` re-keys them.
- **Ownership transfer:** `to` is a member; `Space.owner_account_id` changes, an audit entry is written and `space_updated` is published. Naming the current owner is acknowledged and changes nothing.
- **Profiles and nicknames:** `update_profile` changes only the fields it carries; a patch that changes nothing (none at all included) is acknowledged without an event. `display_name` starts empty and, once set, can be changed but not cleared (it is 1–32 bytes). `set_nickname` on oneself needs `CHANGE_NICKNAME`, even for a holder of `MANAGE_NICKNAMES`; on another member it needs `MANAGE_NICKNAMES` and the member ranked below the actor, so `ADMINISTRATOR` cannot rename the owner or a member at or above its highest role. A change publishes `member_updated` (full form) to every member. From M9 `update_profile`, `set_avatar` and `set_nickname` take a token from the actor's `rate_profile_*` bucket (§ 5), and a member under a timeout cannot change their own (§ 6.16).

### 6.9 Text chat (M3)

Messages, history, reactions, pins, threads, custom emoji, read states, typing, pokes, search, attachments and retention, in text channels (and from M5 in voice channels too, § 6.11). The exact messages and numbers are `yapsta.proto`; this section fixes them first, with § 6.8's conventions (unmarked fields `string`, ids `u64`, times unix seconds, `?` = `optional`, fields numbered from 1 in the order listed, patches never re-send objects).

**Objects**
```
Message{id: u64 = 1, channel_id: u64 = 2, thread_id: optional u64 = 3, author_id: u64 = 4, created_at: u64 = 5,
        content = 6, reply_to: optional u64 = 7, mentions: Mentions = 8, attachments: repeated Attachment = 9,
        reactions: repeated ReactionCount = 10, edited_at: optional u64 = 11, deleted: bool = 12, pinned: bool = 13}
Mentions{account_ids: repeated u64 = 1, role_ids: repeated u64 = 2, channel_ids: repeated u64 = 3,
         everyone: bool = 4, here: bool = 5}
Attachment{id: u64 = 1, media_type = 2, size: u64 = 3, width: u32 = 4, height: u32 = 5, has_thumbnail: bool = 6}
EmojiRef{oneof emoji{unicode: string = 1; custom_id: u64 = 2}}
ReactionCount{emoji: EmojiRef = 1, count: u32 = 2, me: bool = 3}
Thread{id: u64 = 1, channel_id: u64 = 2, name = 3, archived: bool = 4, created_by: u64 = 5, created_at: u64 = 6}
CustomEmoji{id: u64 = 1, name = 2, image_id: u64 = 3, created_by: u64 = 4}
ReadState{channel_id: u64 = 1, last_read_id: u64 = 2, mention_count: u32 = 3, last_message_id: u64 = 4}
```
- **Message ids** are the `messages` row id (§ 7.1): unique space-wide, increasing in commit order, never reused. Clients order a channel's messages by id. `author_id` 0 = a deleted member (§ 7.3). `width` and `height` are 0 when not an image.
- **Threads:** a thread hangs off one top-level message of a text channel, or (M5) a voice channel (its root) and `Thread.id` is the root's message id. Thread messages have `thread_id` set and the root's `channel_id`, so they follow the channel's visibility; the channel's own history never contains them. Threads do not nest.
- **Deleted messages** (§ 7.3) are tombstones: `deleted = true`, `content` empty, no mentions, attachments or reactions, not pinned. They keep their id, author, time, `reply_to` and thread, so replies and threads stay intact.
- **`ReactionCount.me`** (whether the requester reacted) is set only in `Response`s (`message_history`, `get_messages`, `list_pins`, `search`). Events are encoded once for every recipient, so `Message` in an event has `me = false`; clients derive it from the reaction events, which carry `account_id`.
- **`ReadState`:** read states cover a channel together with its threads. `last_read_id` is the newest message of the channel or its threads the account has read (0 = none), `last_message_id` the newest message of the channel or its threads (0 = none), so the channel is unread when `last_message_id > last_read_id`. `mention_count` counts the messages of the channel and its threads with an id above `last_read_id` that mention the account (below). Threads have no read state of their own in M3.

**Commands** (§ 6.8 numbering rules continue; replies as there):

| # | Kind | Fields | Allowed for | Reply |
|---|---|---|---|---|
| 28 | `send_message` | `channel_id`, `thread_id?`, `content`, `reply_to?`, `attachment_ids` | `SEND_MESSAGES` on the channel (in a thread: `SEND_IN_THREADS` instead); `ATTACH_FILES` when `attachment_ids` is not empty; the slowmode and `rate_message_*` | `created_id` |
| 29 | `edit_message` | `message_id`, `content` | its author; `rate_message_*` | `Ack` |
| 30 | `delete_message` | `message_id` | its author, or `MANAGE_MESSAGES` on its channel; from M12 `rate_message_*` | `Ack` |
| 31 | `add_reaction` | `message_id`, `emoji: EmojiRef` | `ADD_REACTIONS` (custom emoji: also `USE_CUSTOM_EMOJI`) on the channel; `rate_message_*` | `Ack` |
| 32 | `remove_reaction` | `message_id`, `emoji: EmojiRef`, `account_id?` (absent = own) | own: members; another's: `MANAGE_MESSAGES` on the channel; from M12 `rate_message_*` | `Ack` |
| 33 | `pin_message` | `message_id` | `MANAGE_MESSAGES` on the channel | `Ack` |
| 34 | `unpin_message` | `message_id` | as 33 | `Ack` |
| 35 | `create_thread` | `message_id`, `name` | `CREATE_THREADS` on the channel; from M9 `rate_message_*` | `created_id` (= `message_id`) |
| 36 | `update_thread` | `thread_id`, `name?`, `archived?` | `MANAGE_THREADS` on the channel, or the thread's creator (from M9 the creator may rename and archive, but `archived = false` needs `MANAGE_THREADS`); from M9 `rate_message_*` | `Ack` |
| 37 | `mark_read` | `channel_id`, `message_id` (a message of the channel or its threads; 0 = nothing read) | `VIEW_CHANNEL` on the channel | `Ack` |
| 38 | `poke` | `account_id`, `text?` | `POKE` (base permissions); `rate_poke_per_min` | `Ack` |
| 39 | `create_emoji` | `name`, `image_id` | `MANAGE_EMOJI` | `created_id` |
| 40 | `rename_emoji` | `emoji_id`, `name` | `MANAGE_EMOJI` | `Ack` |
| 41 | `delete_emoji` | `emoji_id` | `MANAGE_EMOJI` | `Ack` |

Command 38's message is named `PokeMember` (not `Poke`, which is the ephemeral below). No new `CommandResult` kinds. `CreateChannel` gains `retention_days: optional u32 = 11` and `no_history: optional bool = 12`; `UpdateChannel` gains `retention_days: optional u32 = 9` and `no_history: optional bool = 10`; `Channel` gains `retention_days: u32 = 14` and `no_history: bool = 15` (both also in the snapshot form). `UploadImageRequest` gains `purpose: ImagePurpose = 2` with `enum ImagePurpose{UNSPECIFIED = 0, AVATAR = 1, EMOJI = 2}`; `UNSPECIFIED` means `AVATAR`.

**Requests** (§ 6.8; request messages named `<Kind>Request` in CamelCase):

| # | Kind | Fields | Allowed for | Reply (`Response.kind`) |
|---|---|---|---|---|
| 4 | `message_history` | `channel_id`, `thread_id?`, `oneof anchor{before: u64; after: u64; around: u64}` (absent = the newest), `limit` (1–100) | `VIEW_CHANNEL` + `READ_HISTORY` on the channel | `messages` |
| 5 | `get_messages` | `message_ids` (1–100) | members; each message only with `VIEW_CHANNEL` + `READ_HISTORY` on its channel | `messages` (missing and hidden ones left out, in the order asked; a duplicate id counts toward the 1–100 and the reservation, and its message comes back once, at its first place) |
| 6 | `list_pins` | `channel_id` | as 4 | `messages` (newest pin first) |
| 7 | `list_threads` | `channel_id`, `archived: bool`, `before_id?`, `limit` (1–100) | as 4 | `threads` (newest root first) |
| 8 | `search` | `query`, `before_id?`, `limit` (1–25) | members; 20 per minute per account (bucket size = the rate; fixed) | `messages` (newest first) |
| 9 | `upload_attachment` | `data: bytes` | members; from M9 `ATTACH_FILES` on at least one channel the member can see (§ 6.16); `rate_upload_per_min` | `uploaded{blob_id}` (= the attachment id) |
| 10 | `fetch_attachment` | `attachment_id`, `thumbnail: bool` | `VIEW_CHANNEL` + `READ_HISTORY` on its message's channel (a DM message's: § 6.17) | `blob`; `CONFLICT` when the stored file is over 1 MiB − 4 KiB (use `attachment_url`) |
| 11 | `attachment_url` | `attachment_id`, `thumbnail: bool` | as 10 | `url` |
| 12 | `upload_url` | `size: u64` | as 9 | `upload_slot` |

`Response.kind` adds `messages: MessageList{messages: repeated Message = 1, has_more: bool = 2} = 4`, `threads: ThreadList{threads: repeated Thread = 1, has_more: bool = 2} = 5`, `url: SignedUrl{url = 1, expires_at: u64 = 2} = 6` and `upload_slot: UploadSlot{attachment_id: u64 = 1, url = 2, expires_at: u64 = 3} = 7`. `message_history` returns up to `limit` messages in ascending id order; `has_more` says more exist beyond the page in the anchor's direction (for `around`, on either side). `attachment_url` and `upload_url` are `CONFLICT` while `https_listen` is `off`. A message list reserves 6 KiB per message it can return (§ 6.1): × `limit`, × the number of ids asked for `get_messages`, × 50 for `list_pins`; `list_threads` 512 B × `limit`, `fetch_attachment` the stored size + 1 KiB (its over-size check runs with the read-only checks, before the reservation, so it never reserves more than about 1 MiB), the others 1 KiB.

**Typing** is a new `Envelope` body, `start_typing: StartTyping{channel_id: u64 = 1, thread_id: optional u64 = 2} = 18`, sent with `request_id = 0` and never answered (one with `request_id` ≠ 0 is `INVALID`): one is accepted per (account, channel or thread) every 3 s, or since that account's last message there, and at most 3 per account in any 3 s across all of them (a session's typings closer than 250 ms to the last one it sent on are dropped before any check); the rest are dropped, as are those the sender may not send to (it needs the permission `send_message` would, in an open thread of that channel, outside a timeout), checked again when it is sent on. One admitted before that account's message on the same channel or thread was committed is dropped, so none arrives after the message. Clients show the indicator for 8 s, or until that account's message arrives.

**Events** (`Event.kind`, continuing from 13):

| # | Kind | Message | Delivered to |
|---|---|---|---|
| 14 | `message_created` | `MessageCreated{message: Message = 1}` | members with `VIEW_CHANNEL` on its channel |
| 15 | `message_updated` | `MessageUpdated{message: Message = 1}` (an edit; full form) | as 14 |
| 16 | `message_deleted` | `MessageDeleted{channel_id: u64 = 1, message_id: u64 = 2}` | as 14 |
| 17 | `reaction_added` | `ReactionAdded{channel_id: u64 = 1, message_id: u64 = 2, emoji: EmojiRef = 3, account_id: u64 = 4}` | as 14 |
| 18 | `reaction_removed` | `ReactionRemoved{` as 17 `}` | as 14 |
| 19 | `message_pinned` | `MessagePinned{channel_id: u64 = 1, message_id: u64 = 2, pinned_by: u64 = 3}` | as 14 |
| 20 | `message_unpinned` | `MessageUnpinned{channel_id: u64 = 1, message_id: u64 = 2}` | as 14 |
| 21 | `thread_created` | `ThreadCreated{thread: Thread = 1}` | as 14 (the thread's channel) |
| 22 | `thread_updated` | `ThreadUpdated{thread: Thread = 1}` | as 21 |
| 23 | `emoji_created` | `EmojiCreated{emoji: CustomEmoji = 1}` | every member |
| 24 | `emoji_updated` | `EmojiUpdated{emoji: CustomEmoji = 1}` | every member |
| 25 | `emoji_deleted` | `EmojiDeleted{emoji_id: u64 = 1}` | every member |

None of them is a visibility change (§ 6.3). Retention pruning publishes nothing: clients drop what scrolls out of retention themselves.

**Ephemerals** (`Ephemeral.kind`, continuing from 2): `typing: Typing{channel_id: u64 = 1, thread_id: optional u64 = 2, account_id: u64 = 3} = 3`, to the sessions with `VIEW_CHANNEL` on the channel except the sender's own; `poke: Poke{from_account_id: u64 = 1, text = 2} = 4`, to the target account's sessions; `read_state: ReadState = 5`, to the account's other sessions when `mark_read` changes it. Changes that follow from messages (an own message, a mention) are not sent: every session derives them from `message_created`, and an account's own message clears its `mention_count` for that channel as `mark_read` would. A poke to an account with no session is acknowledged and goes nowhere.

**Snapshot and resume:** `Snapshot` adds `read_states: repeated ReadState = 10` (every visible text channel, and from M5 every voice channel the session may read, § 6.11) and `emoji: repeated CustomEmoji = 11` (all of the space's); `Resumed` adds `read_states: repeated ReadState = 2`, since read states travel as ephemerals and are not replayed. A `resync` carries both, like any snapshot. Read states are authoritative in memory while the account has a session: loaded from `read_states` and `message_mentions` (§ 7.1) for its first session, changed by `mark_read` and by new messages, and written back coalesced (§ 7.2). The load is a sequenced step: it goes through the space's commit queue like a commit, so it sees every message committed before it, and the hub applies every later one to the loaded copy. While a copy exists (the account is online, or offline with a write still pending) a new session uses it and nothing is loaded; the copy is dropped only after the write that follows the account's last session. The snapshot, `resync` and `Resumed` read that copy, never the database, so a read state is never older than the last `Ack`ed `mark_read`. `mention_count` is computed at load for the channels the account sees then, with its roles then, and a new message adds to it when it mentions the account in a channel the account sees at that moment; a channel that becomes visible later starts at 0 until the next load. It is a badge, not an exact count. It counts at most 1,000 messages per channel. The load reads them with one statement per channel, in three parts: the account, its roles, and @everyone / @here. Each part takes at most the newest 1,000 from its own partial index, and the parts are merged. The account and @everyone / @here parts walk their index without a sort; the role part sorts only the account's own role mentions in range. So a channel's read in the writer does not grow with every mention in range (#378). A crash can lose up to the last 5 s of `mark_read`s.

**Rules**
- **Check order** is § 6.8's. Checks on a message (it exists, its channel is visible, its author, its thread's state) run inside the writer job that commits the change (`BEGIN IMMEDIATE`, § 7.2), since messages are not held in memory; § 4's step 1 covers the in-memory part. Commits are pipelined (a later job can be queued behind a permission change not yet applied), so permissions captured before the job may be stale: the job therefore checks the actor's permission on the message's channel from the rows it reads in its own transaction (the owner, the actor's roles, the channel's ancestor overwrites), with the § 8 engine of `crates/core` (pure, no I/O); the in-memory check before the job is only an early refusal, and the writer never asks the core. This holds for every M3 writer job that depends on a channel permission, `send_message` (its send, attachment and mention permissions) included. A test queues a revocation and a command that needs the revoked permission back to back and expects `FORBIDDEN` (or `NOT_FOUND`). Rate-limit tokens are taken before the job, whatever its outcome. A message in a channel the actor cannot see is `NOT_FOUND`, the same reply as a missing id. Commands and requests on messages only work in `TEXT` channels, and from M5 in `VOICE` channels too (§ 6.11); in categories they are `NOT_FOUND`.
- **Text:** `content` is free text (§ 6.8) of 1–4,000 bytes, or 0–4,000 with at least one attachment; a thread `name` 1–100 bytes (from M9 under § 6.8's name rules) and an emoji `name` 2–32 bytes of `[a-z0-9_]`, unique in the space; a poke `text` 0–100 bytes (from M9 under § 6.8's name rules, since it is shown as a notification); a Unicode reaction 1–32 bytes with no whitespace and no `Cc` or `Cf` character except U+200D. Clients render all of it as text (§ 9). A `search` query is 1–256 bytes.
- **Sending:** `reply_to` names a message in the same channel and thread (a deleted one is fine). A thread must not be archived (`CONFLICT`). `attachment_ids` lists 0–10 of the sender's own pending attachments (`NOT_FOUND` otherwise, `CONFLICT` for an upload slot not yet completed); sending attaches them to the message for good. Slowmode: one message per `slowmode_secs` per member and channel, where each thread counts as a channel of its own; `MANAGE_MESSAGES` or `MANAGE_CHANNELS` on the channel bypasses it; a message too early is `RATE_LIMITED` with `retry_after_ms`. A member whose `timeout_until` (§ 7.1) is in the future may not send, edit, react, create threads or poke (`FORBIDDEN`); from M9 nor update a thread, change their profile, avatar or own nickname (§ 6.16).
- **Editing** replaces `content` and sets `edited_at`; no older version is kept anywhere, and the resume ring is updated as on deleting (§ 6.3). Mentions are parsed again; attachments cannot change. A deleted message cannot be edited (`CONFLICT`).
- **Deleting** turns the message into its tombstone in the same transaction: content, mentions, reactions, the pin and the attachment rows go (the files follow by blob GC, § 6.5), and the resume ring is redacted (§ 6.3). Deleting a tombstone is acknowledged. A deleted thread root keeps its thread.
- **Mentions** are parsed by the server from `content`; clients never send them. Tokens: `<@account_id>`, `<@&role_id>`, `<#channel_id>`, `@everyone`, `@here`, in decimal ids. Only ids of existing members and roles, and of channels the author can see, count (clients show a channel id they do not know as plain text); a role mention needs `MENTION_ROLES`, `@everyone` and `@here` `MENTION_EVERYONE` on the channel, otherwise the token stays plain text and mentions nobody. At most 50 ids per message are kept, all kinds together, in order of appearance. A message mentions an account when it names it, a role it holds, or carries `@everyone` or `@here` (both counted alike for `mention_count`), and only while the account can see the channel; the author never mentions themself. Mentions are stored per message (`message_mentions`, § 7.1).
- **Reactions:** at most 20 distinct emoji per message (`CONFLICT` for a new one past that); each account reacts once per emoji, so adding an existing reaction or removing a missing one is acknowledged without an event. A custom emoji must exist when added (`NOT_FOUND`); deleting an emoji keeps the reactions that use it, and clients show them as unknown. No reactions on tombstones (`CONFLICT`).
- **Pins:** at most 50 per channel (`CONFLICT`); pinning a pinned message or unpinning an unpinned one is acknowledged without an event. Thread messages cannot be pinned (`INVALID`), nor deleted ones (`CONFLICT`).
- **Threads:** the root is a top-level message that is not a tombstone (`INVALID` otherwise); one thread per root (`CONFLICT`). Archived threads accept no messages; `update_thread` with `archived = false` reopens one (from M9 only with `MANAGE_THREADS`, so a creator cannot undo a moderator's archive). From M9 a moderator deletes a thread with `delete_thread` (§ 6.16).
- **Read states:** when a member joins (claim, invite, from M7 open join, fixture), a read state is created for each existing text channel (and from M5 voice channel) at its newest message, so a new member starts with everything read; channels created later start at 0. `mark_read` may name any message of the channel or its threads, older ones included (marking unread), or 0. Each new message updates the in-memory read states of the online accounts that see the channel (`last_message_id`, and `mention_count` for those it mentions); an account's own message marks its channel read up to it.
- **Pokes** go to a member (`NOT_FOUND` otherwise) and are never stored.
- **Custom emoji:** at most 200 per space (`CONFLICT`). `image_id` is the actor's own pending upload made with `upload_image` and purpose `EMOJI` (the purpose is stored with the upload, § 7.1), which re-encodes it to at most 128 × 128 px WebP (§ 6.5); `set_avatar` and `set_space_icon` take only purpose `AVATAR`, and the wrong purpose is `NOT_FOUND`. Deleting an emoji deletes its image's attachment. `fetch_blob` (§ 6.8) also serves an emoji's `image_id`.
- **Search:** the server parses `query`, never FTS5 or SQL. Words are split on whitespace. `from:<account_id>`, `in:<channel_id>` and `has:file`, `has:image` or `has:link` filter (each at most once; `has:link` means the content contains `http://` or `https://`). A `"…"` run is a phrase. Every other word becomes a quoted FTS5 term (`"` doubled inside it), and all terms must match. The built `MATCH` string and the filter ids are bound parameters, never formatted into SQL. A query with no term and no filter, or one that does not parse, is `INVALID`. Results are limited in SQL to the channels where the actor holds `VIEW_CHANNEL` and `READ_HISTORY`, never trimmed after the query, and never include tombstones. At most 2 searches run at once (the rest wait up to 2 s, then are answered `RATE_LIMITED` with `retry_after_ms`), and one running over 2 s (waiting for a database reader included) is interrupted and answered `RATE_LIMITED` with `retry_after_ms` (the connection stays open; over QUIC a refused request is a stream reset carrying the code alone, § 6.1, so `retry_after_ms` reaches TCP clients only). Thread messages are found too. The query is user data: never logged (§ 7.6).
- **Retention:** `retention_days` 0 keeps messages forever (the default), 1–3,650 deletes messages older than that many days; `no_history` deletes them once they are older than `resume_ring_secs`. Until then such messages are ordinary rows: history, `get_messages`, pins, threads, replies, search and moderation work on them; afterwards they are gone as if pruned. Both are text-channel settings, and from M5 voice-channel ones too (`INVALID` on a category). Pruning works as deleting (§ 7.3, § 7.4) but leaves no tombstone and publishes nothing. A pruned thread root leaves its thread, which goes once it has no messages.
- **Limits** count per space and are not configurable in M3: 10 attachments per message, 20 distinct reactions per message, 50 pins per channel, 200 custom emoji, 10 pending attachments per account (§ 6.5).
- **Content in logs:** message content, edit text, search queries, poke text, emoji names, attachment bytes and signed URLs are user data or secrets: never in logs, `Error.message` or metrics. These messages get a hand-written redacting `Debug`, so printing an `Envelope` never shows such text or bytes: `SendMessage`, `EditMessage`, `Message`, `EmojiRef`, `Thread`, `CreateThread`, `UpdateThread`, `SearchRequest`, `PokeMember`, `Poke`, `CustomEmoji`, `CreateEmoji`, `RenameEmoji`, `UploadAttachmentRequest`, `UploadImageRequest`, `BlobData`, `SignedUrl` and `UploadSlot` (the messages that contain these inherit it).

### 6.10 Voice (M4)

Voice channels, datagram routing, talk power, priority speaker, whisper, mute and deafen, move and disconnect, and temporary channels. The exact messages and numbers are `yapsta.proto`; this section fixes them first, with § 6.8's conventions. Datagrams themselves are § 6.4.

**Objects**
```
VoiceState{account_id: u64 = 1, channel_id: u64 = 2, session_ref: u32 = 3, self_mute: bool = 4,
           self_deaf: bool = 5, server_mute: bool = 6, server_deaf: bool = 7, priority: bool = 8}
VoiceSession{session_ref: u32 = 1, channel_id: u64 = 2}
```
- `VoiceState` is an account's place in voice. `channel_id` 0 means "not in voice" (sent when a member leaves, and to those who can no longer see where they went); `session_ref` is then 0 too.
- **One voice presence per account.** An account is in at most one voice channel, from one session. A `join_voice` from another of its sessions moves the account's voice to that session: the old session leaves voice.
- **`session_ref`** is a `u32` from one server-wide counter, minted on every join and every move (a move by a moderator included), starting at 1 and never reused while the process runs, so a datagram in flight from an earlier join is never attributed to the wrong speaker. 0 = none. It is not derived from the account and means nothing across restarts.
- **`VoiceSession`** tells a session its own voice membership: the `session_ref` its datagrams must carry and the channel, or 0 and 0 once it is out of voice. `VoiceState` cannot say which of an account's sessions is in voice; this does.

**Commands** (§ 6.8 numbering rules continue; replies as there):

| # | Kind | Fields | Allowed for | Reply |
|---|---|---|---|---|
| 42 | `join_voice` | `channel_id`, `password?` | `CONNECT` on a voice channel; not full (`max_members`) unless `JOIN_FULL_CHANNEL`; its password unless `BYPASS_CHANNEL_PASSWORD`; `rate_voice_per_min` | `Ack` |
| 43 | `leave_voice` | — | members | `Ack` |
| 44 | `set_voice_state` | `self_mute?`, `self_deaf?`, `priority?` | in voice; `priority = true` needs `PRIORITY_SPEAKER` on the channel; 10 per 10 s per account (fixed) | `Ack` |
| 45 | `set_member_voice` | `account_id`, `server_mute?`, `server_deaf?` | `MUTE_MEMBERS` (for `server_mute`) and `DEAFEN_MEMBERS` (for `server_deaf`) on the target's voice channel, or in the base permissions when the target is not in voice; the target ranked below the actor | `Ack` |
| 46 | `move_member` | `account_id`, `channel_id` | `MOVE_MEMBERS` on the target's current channel and on the new one; the target ranked below the actor, or the actor themself | `Ack` |
| 47 | `disconnect_member` | `account_id` | `MOVE_MEMBERS` on the target's channel; the target ranked below the actor | `Ack` |
| 48 | `set_whisper_list` | `list_id: u32`, `account_ids`, `channel_ids`, `role_ids` | members; `rate_voice_per_min` | `Ack` |
| 49 | `clear_whisper_list` | `list_id: u32` | members | `Ack` |

Their messages, with § 6.8's numbering (`?` fields are `optional`):
```
JoinVoice{channel_id: u64 = 1, password: optional string = 2}    LeaveVoice{}
SetVoiceState{self_mute: optional bool = 1, self_deaf: optional bool = 2, priority: optional bool = 3}
SetMemberVoice{account_id: u64 = 1, server_mute: optional bool = 2, server_deaf: optional bool = 3}
MoveMember{account_id: u64 = 1, channel_id: u64 = 2}    DisconnectMember{account_id: u64 = 1}
SetWhisperList{list_id: u32 = 1, account_ids: repeated u64 = 2, channel_ids: repeated u64 = 3, role_ids: repeated u64 = 4}
ClearWhisperList{list_id: u32 = 1}
```
No new `CommandResult` or `Request` kinds. `CreateChannel` gains `temporary: optional bool = 13`; `Channel` gains `temporary: bool = 16` (also in the snapshot form). `UpdateChannel` cannot change it.

**Events** (`Event.kind`, continuing from 25): `voice_state_updated: VoiceStateUpdated{state: VoiceState = 1, previous_channel_id: u64 = 2} = 26`, the account's whole state after any change (join, leave, move, a self or server flag, `priority`), and the voice channel it was in before (0 = none; equal to `state.channel_id` for a flag change). It goes to every session that can see the new channel or the previous one, and each gets the form it may see: `previous_channel_id` is 0 in a copy for a session that cannot see the previous channel, and a session that can see only the previous channel gets the state with `channel_id` 0, `session_ref` 0 and every flag false, as for a leave. So a member never learns about a channel they cannot see, and a leave or a move into a hidden channel still reaches everyone who saw the member before. The filter and the forms are the same on replay from the ring; this event is therefore not encoded once for every recipient: the ring keeps it once, counted at its full form against `resume_ring_bytes`, and the other forms are built when it is sent or replayed. It is not a visibility change (§ 6.3).

**Ephemerals** (`Ephemeral.kind`, continuing from 5): `voice_session: VoiceSession = 6`, to one session whenever its own voice membership changes: on its join (written before the `Ack`), its leave, a move or disconnect by a moderator, another of the account's sessions taking the voice over, and an eviction (below). A session that is not told otherwise is not in voice; a new connection, a resume included, starts outside voice.

**Snapshot:** `Snapshot` adds `voice_states: repeated VoiceState = 12`, the states in voice channels the session can see. Voice state events are persistent (§ 6.3), so a replay brings them; `Resumed` gains nothing. Speaking indicators are not sent by the server: clients derive them from the datagrams they receive (and the `EOT` flag), so the control stream carries nothing per word spoken; a deafened session receives no datagrams and so shows none. Routes change before the matching event is published and datagrams travel apart from the control stream, so a client can receive a datagram whose `session_ref` it cannot map yet; it holds or drops it.

**State and storage.** Voice membership and the self flags live in memory only (§ 4): they end with the connection (a close, the 60 s idle timeout, `SESSION_REPLACED`, `MEMBER_REMOVED`) and with a restart, and after a resume the client joins again. `server_mute` and `server_deaf` are stored per member (§ 7.1, M4) and apply whenever the member is in voice (except as in Moderation below), so leaving and rejoining does not lift them. A voice change with no row to write (join, leave, a self flag, move, disconnect, an eviction) never touches the database: the core applies it in its own apply step, which validates against the in-memory state and publishes it with the next `seq`. Changes still waiting for their commit have no `seq` yet, so voice events stay in one order with every other event, and voice keeps working when the writer is busy or failing. `set_member_voice` writes its row and follows § 4's order. This is the one exception to § 4's "a client that receives an event can read the matching row": there is no row. When a connection ends, the core takes its session out of voice in the same step that removes the session, and only if that session still holds the account's voice (another device may have taken it over). When a device's new connection replaces its older session (`SESSION_REPLACED`, a resume), the older session leaves voice first, so the replay or snapshot the new session gets already shows the account out of voice.

**Rules**
- **Check order** is § 6.8's, except that the password comes last. `join_voice`: the channel exists and is visible (`NOT_FOUND`); `CONNECT` (`FORBIDDEN`); it is a voice channel and a password is 1–64 bytes (`INVALID`); the session is already in it (acknowledged without an event, nothing else checked); the session has a voice path (below), the channel is not full and the space is under its 1,000 accounts in voice (`CONFLICT`); then the rate limit (`RATE_LIMITED`); then, for a channel with a password and without `BYPASS_CHANNEL_PASSWORD`, the password (`FORBIDDEN` when missing or wrong), checked with argon2id off the tokio workers in the claim code's pool (§ 6.2), at most 2 at once. A password sent to a channel without one is ignored. Wrong passwords are limited further: 5 per account per 10 minutes (fixed), checked after the `rate_voice_per_min` token is taken and only for joins that would hash a password (never for `BYPASS_CHANNEL_PASSWORD`); past that, such a join is `RATE_LIMITED` with `retry_after_ms` before any hash, so guessing costs days, not minutes. Only a wrong password counts: a right one, a missing one, or one the server could not check (the hash pool full, the store failing: `UNAVAILABLE`) does not.
- **Voice path.** Voice needs QUIC datagrams (§ 6.4). `join_voice` from a TCP session, or from a QUIC session whose peer did not negotiate datagrams, is `CONFLICT` with fixed text; the connection stays open. There is no capability flag: the transport shows it.
- **Full** means `max_members` voice members (0 = no limit), not counting the joining account itself, so taking the account's voice over from another device in the same channel always fits. A space has at most 1,000 accounts in voice at once (a join past that is `CONFLICT`), which bounds `Snapshot.voice_states`. A member moved in by a moderator does not count against the check, and neither `max_members` nor the password applies to a move.
- **Who is heard.** A session's datagrams on the channel route are forwarded only while it may speak: `SPEAK` on the channel, talk power at least the channel's `needed_talk_power` (§ 8.2), not `self_mute`, not `server_mute`, and no `timeout_until` in the future. A member under a timeout may join and listen. They go to every other voice session in the channel that is not `self_deaf` or `server_deaf` (the sender never gets its own). Self mute and deafen are enforced by the server too, which saves the bandwidth; deafen does not imply mute.
- **Priority speaker.** `priority` marks the member as a priority speaker; clients lower the other speakers while a priority speaker's datagrams arrive. It needs `PRIORITY_SPEAKER` on the channel when set; it is cleared, with an event, on a move and when the permission is lost. There is no header bit for it.
- **Moderation.** A target in voice in a channel the actor cannot see is treated, in every check and reply, as not in voice, so moderation never reveals where a member is. A flag stored that way takes effect at the target's next join or move, never in the hidden channel they are in, so it cannot override that channel's permissions. An actor who can see the target's channel compares and sets against the flags in effect there, so a flag already stored but not yet in effect is applied, with its event. `set_member_voice` changes only the flags it carries; a change that changes nothing is acknowledged without an event. It applies to members not in voice too (stored for their next join; no event until then). `move_member` needs a voice channel the target can see and holds `CONNECT` on (`CONFLICT` otherwise; `max_members` and the password do not apply) and moves the account's voice session there with a new `session_ref`; moving a member into the channel they are in is acknowledged without an event. `disconnect_member` takes the target out of voice. Both are `CONFLICT` when the target is not in voice. Hierarchy is § 6.8's; the owner passes it.
- **Evictions.** When a member loses `CONNECT` or `VIEW_CHANNEL` on their voice channel, the channel is deleted or the membership ends, they leave voice (an event, and `voice_session` to their session) in the apply step of that change, before its events are published. Losing `SPEAK` or talk power, or a timeout, only stops forwarding. Moving a channel keeps its voice members.
- **Routing changes come first.** Every change that affects who is heard or who hears (the above, roles, talk power, overwrites, `needed_talk_power`, the flags, whisper lists) rebuilds the routes of the affected channels and sessions in its apply step, before its events are published; datagrams are never checked against permissions one by one (§ 6.4).
- **Whisper.** A whisper list is registered per session under a `list_id` of 1–8; registering an existing `list_id` replaces the list and `clear_whisper_list` removes it (a missing one is acknowledged). A list names at most 50 accounts, 10 channels and 10 roles (more is `INVALID`); ids that do not exist are accepted and reach nobody, so a list never reveals what exists. Lists belong to the voice membership they were registered in: a join, a move or leaving voice drops them all, so a datagram sent before a move can never reach recipients chosen under the new channel's rules; the client registers its lists again after the `voice_session` that announces the change. `set_whisper_list` outside voice is `CONFLICT`, checked before the rate limit. A `join_voice` to the channel the session is already in is not a join here and keeps the lists. The first 8 `set_whisper_list` of each voice membership cost nothing, so re-registering after a move never runs into `rate_voice_per_min`; later ones take a token. `@everyone` (role 1) cannot be listed (`INVALID`). A route-1 datagram whose `ref` is the list's `list_id` goes to the voice sessions of the listed accounts, the voice members of the listed channels, and the voice members holding a listed role, each once, minus the sender and the deafened, and only to recipients in a voice channel the sender can see who can see the sender's voice channel (so every recipient can tell who whispers, § 6.4 "senders are identified"). The sender is in voice, not muted or timed out, and has `WHISPER` on its own channel. Every recipient, however listed, also needs the sender to be able to speak in the recipient's channel (`SPEAK` and talk power, § 8.2), the sender's own channel included, so whisper never bypasses talk power. Lists are resolved to sessions whenever routes are rebuilt, so a target that stops qualifying stops receiving from the next datagram.
- **Temporary channels.** `create_channel` with `temporary = true` makes a voice channel (`INVALID` for other kinds) and needs `CREATE_TEMP_CHANNEL` on the parent (in the base permissions at the top level) instead of `MANAGE_CHANNELS`. At most 50 per space (`CONFLICT`); they count toward the 500 channels. Creating one takes a token from `rate_voice_per_min`. A temporary channel cannot have children (`INVALID` for `create_channel` or `move_channel` that would put a channel under it). It is stored like any channel and deleted through the normal delete path (`channel_deleted`) once it has been empty for 60 s, counted from its creation or from its last voice member leaving, and a join within that time keeps it, so a member who reconnects does not lose it; at startup, before the listeners open, every temporary channel is deleted, since no one is in voice after a restart. Otherwise it is an ordinary channel (`update_channel`, `set_channel_password`, overwrites).
- **Limits** count per space or session and are not configurable in M4: one voice presence per account, 8 whisper lists per session, 50 accounts, 10 channels and 10 roles per list, 50 temporary channels. `set_voice_state` is limited to 10 per 10 s per account (bucket 10), taken before its checks whatever their outcome (`RATE_LIMITED` with `retry_after_ms` past it): a flag change writes no row, so nothing else paces the events it publishes, and a member toggling a flag could otherwise fill the queues of everyone who sees the channel and the resume ring. Datagrams: at most 120 per second per sending session, both routes together (bucket size 60, fixed): enough for 20 ms frames on the channel and a whisper at once; the rest are dropped. From M9 also at most 64,000 bytes a second per sending session (whole datagrams, header included; bucket 64,000, fixed): two 192 kbit/s music streams at 20 ms are about 50,000, and one sender can no longer push 1.15 Mbit/s to every listener; over it, datagrams are dropped and counted with a reason of their own (§ 6.16).
- **Secrets and logs.** `JoinVoice` carries a channel password and gets a hand-written redacting `Debug`. Voice payloads, header `seq` and `timestamp`, and peer addresses never appear in logs, `Error.message` or metrics; dropped datagrams are counted, never logged (§ 7.6).

### 6.11 Styles (M5)

A space is run either **voice-first** or **text-first**:
- **Voice-first** (TeamSpeak-like): members sit in voice channels, land in a lobby on connect, and chat in the channel they are in.
- **Text-first** (Discord-like): text channels are the main place, and members join voice by choice.

The space says which style it is, and clients lay themselves out by it. M5 adds:
- the style and its feature switches as space settings;
- chat in voice channels, with a rule for who reads it;
- lobby on connect;
- starter templates;
- server-side enforcement of the switches.

The exact messages and numbers are `yapsta.proto`; this section fixes them first, with § 6.8's conventions. (Protocol minors stop matching milestone numbers here: M5 is minor 5, and later milestones take later minors.)

**Objects**
```
enum SpaceStyle{UNSPECIFIED = 0, VOICE_FIRST = 1, TEXT_FIRST = 2}
enum VoiceChatAccess{UNSPECIFIED = 0, MEMBERS_IN_CHANNEL = 1, CHANNEL_VIEWERS = 2}
enum StarterTemplate{UNSPECIFIED = 0, GAMING = 1, COMMUNITY = 2, SMALL_TEAM = 3}
Space gains: style: SpaceStyle = 6, lobby_on_connect: bool = 7, threads: bool = 8, reactions: bool = 9,
             member_list: bool = 10, voice_chat_access: VoiceChatAccess = 11,
             default_voice_channel: optional u64 = 12
SpacePublicInfo gains: style: SpaceStyle = 6
UpdateSpace gains: style: optional SpaceStyle = 4, lobby_on_connect: optional bool = 5, threads: optional bool = 6,
                   reactions: optional bool = 7, member_list: optional bool = 8,
                   voice_chat_access: optional VoiceChatAccess = 9, default_voice_channel: optional u64 = 10
```
- **`Space` fields:** the new fields are in both the snapshot form and the full form. They travel in the snapshot, `get_space` and `space_updated` (event 3, every member). There is no new event kind: a change of any of them is one `space_updated`. `default_voice_channel` is formed per recipient: it is left absent for a session without `VIEW_CHANNEL` on that channel, so no member learns the id of a channel they cannot see (§ 6.10). As for `voice_state_updated`, the ring keeps one full form of `space_updated` and the other form is derived when it is sent or replayed; `get_space`, the snapshot and `resync` use the per-recipient form too.
- **`SpacePublicInfo`:** it carries the style only, so a join screen can show it before joining. The switches and the default channel are for members.
- **Names:** the wire names are `VOICE_FIRST` and `TEXT_FIRST`, not product names. Clients choose their own labels.
- **Never sent:** a server never sends an `UNSPECIFIED` value.
- **Switches:** `threads`, `reactions` and `member_list` switch those features; `voice_chat_access` is the reader rule below. `lobby_on_connect` and `default_voice_channel` are lobby on connect (below).
- **`member_list`** is presentation only. It tells clients whether to show a member panel; the server sends the same data either way.

**`update_space` (command 2)** keeps its permission, `MANAGE_SPACE`, and its patch semantics: an absent field stays as it is.
- An `UNSPECIFIED` enum value, or any value outside the ones listed (prost enums are open), is `INVALID`; the same holds for `apply_template`. A client that receives a `style` or `voice_chat_access` it does not know (from a newer server) treats it as `TEXT_FIRST` / `CHANNEL_VIEWERS` for layout and changes nothing it does not understand.
- `default_voice_channel` names a voice channel that is not temporary (§ 6.10): `NOT_FOUND` if it is missing or not visible to the actor, `INVALID` for another kind or a temporary one. `0` clears it, since ids start at 1.
- Setting `style` does not change any switch. A client that changes the style sends the style's defaults with it, in the same patch:

  | Switch | `VOICE_FIRST` | `TEXT_FIRST` |
  |---|---|---|
  | `lobby_on_connect` | on | off |
  | `threads` | off | on |
  | `reactions` | on | on |
  | `member_list` | off | on |
  | `voice_chat_access` | `MEMBERS_IN_CHANNEL` | `CHANNEL_VIEWERS` |

**Defaults:**
- A new space (§ 6.8: created by `init`) starts `VOICE_FIRST` with its defaults, and no `default_voice_channel`.
- The M5 migration gives these defaults to a space with no owner and no channels, which is a fresh one.
- Every other space, an instance already in use, gets `TEXT_FIRST` with its defaults, so M3 and M4 behaviour does not change on upgrade.

**Deleting the default channel:** deleting the `default_voice_channel` with `delete_channel` clears it in the same transaction (a temporary channel cannot be the default, so the reaper never deletes one). That commit publishes `space_updated` after `channel_deleted`.

**Commands** (§ 6.8 numbering rules continue; replies as there):

| # | Kind | Fields | Allowed for | Reply |
|---|---|---|---|---|
| 50 | `apply_template` | `template: StarterTemplate` | `MANAGE_CHANNELS` and `MANAGE_ROLES` in the base permissions, and every permission the template's roles and overwrites allow (§ 6.8 hierarchy: never grant what one does not hold), and from M9 talk power at least each template role's; setting the default channel also needs `MANAGE_SPACE` | `Ack` |

Its message is `ApplyTemplate{template: StarterTemplate = 1}`. There are no new `Request`, `CommandResult`, event, ephemeral or `ErrorCode` kinds in M5.

**Messages in voice channels.** From M5, every § 6.9 command and request, and every § 6.9 rule, applies to `VOICE` channels as it does to `TEXT` channels:
- messages, history, replies, edits, deletes, reactions, pins, threads, attachments, mentions, typing, read states, search, slowmode, retention and `no_history`;
- the § 6.9 events and ephemerals, delivered as for a text channel except under `MEMBERS_IN_CHANNEL` (below).

`CATEGORY` channels still have no chat (`NOT_FOUND`). Deleting a voice channel, a temporary one included, queues its messages for purging like a text channel's (§ 7.2).

**Who reads a voice channel's chat** (`voice_chat_access`):
- **`CHANNEL_VIEWERS`:** as for a text channel. `VIEW_CHANNEL` on it reads live chat and typing, and `READ_HISTORY` too reads history, pins, threads, search hits and attachments. Sending needs the § 6.9 permissions.
- **`MEMBERS_IN_CHANNEL`:** the same permissions, and the account must also have its voice presence (§ 6.10) in that channel now.
  - The owner, and holders of `MANAGE_MESSAGES` on the channel, are exempt: they read and moderate without joining voice.
  - While the condition holds, history includes the messages from before the join.
  - Everyone else is treated, for that channel's chat, as if they could not see it:
    - they receive none of its message, reaction, pin and thread events and none of its typing;
    - the snapshot, `resync` and `Resumed` carry no read state for it;
    - `message_history`, `get_messages`, `list_pins`, `list_threads`, `fetch_attachment`, `attachment_url` and its search hits are left out or `NOT_FOUND`;
    - `send_message`, `mark_read`, reactions, pins, threads and typing are `NOT_FOUND` or dropped.
  - The channel itself, its voice states and its voice stay as § 6.10 says.
- **When readership is recomputed:** the set of voice channels each session may read is part of its cached view (§ 8.4). It is recomputed in the apply step of every voice join, leave, move, disconnect and eviction, of every `space_updated` that changes `voice_chat_access` or the owner, and of every change that can alter the session's permissions (`role_*`, `overwrite_*`, the member's roles, a channel move or delete), before that change's events are fanned out.
  - A session that gains a channel gets `read_state` (ephemeral 5) for it.
  - A session that loses a channel gets nothing more; the voice event tells it why.
  - A `space_updated` that changes `voice_chat_access` is a visibility change for the resume rule (§ 6.3).
- **Resume:** replays pass the same filter as live fan-out (§ 6.3), against the session's readership at the moment of the resume. A resumed session starts outside voice (§ 6.10), but its account may still be in the channel on another device, and the owner and `MANAGE_MESSAGES` holders read without voice; they get the gap's chat events. Everyone else gets none of them, and reads what it missed through history once it is in the channel again (history includes messages from before the join).
- **The writer exception.** Voice membership has no row, so the writer job cannot recheck it the way § 6.9 rechecks permissions from the rows in its own transaction.
  - Every chat request and command on a voice channel asks the hub, on its request path and before it queues any writer job or database read, for the session's minor and the voice channels it may read (one hop on the hub's queue, like `visible`); the writer job itself never asks the hub or the core (§ 6.9). Under `MEMBERS_IN_CHANNEL` that is the early refusal; for events, fan-out is authoritative.
  - **Request results are checked again before they leave.** `message_history`, `get_messages`, `list_pins`, `list_threads`, `search`, `fetch_attachment` and `attachment_url` ask the hub a second time, after their database read and before the reply is sent (or a URL is signed): results from a voice channel the session may no longer read are left out (a single-channel request is answered `NOT_FOUND`; search hits are filtered by this second answer too, though its SQL was already limited by the first), so a member who leaves voice while a request waits for a reader never receives what it read. A test pauses such a request after its read, takes the account out of voice, resumes it, and expects the channel's results gone.
  - A message from a sender who leaves voice while it commits is kept, and reaches only the sessions that may read the channel then.
  - Search passes the ids of the voice channels the actor may read under this rule into its SQL as a bound parameter list, read from the hub when the search starts.
  - A signed attachment URL issued while the session could read the channel keeps working until it expires (at most 10 min, § 6.5), as for any lost access; leaving voice is the common case of that here.
- **Read states and mentions:** the in-memory read states, their load and the rows created at a member's join cover every voice channel the account has `VIEW_CHANNEL` on, whatever its voice presence; `last_message_id` and `mention_count` advance for all of them as for text channels (the stored `message_mentions` are the truth, § 6.9). `MEMBERS_IN_CHANNEL` gates only delivery: the snapshot, `resync`, `Resumed` and the `read_state` ephemeral carry a voice channel's read state only while the session may read it. So a member who joins the channel sees the badge of what was said while they were out.

**Switch enforcement.** The server enforces the switches, not only clients:
- **`threads` off:** `create_thread` is `FORBIDDEN` with fixed text. Existing threads stay readable, and messages may still be sent in them; `update_thread` works as before.
- **`reactions` off:** `add_reaction` is `FORBIDDEN` with fixed text. Reactions already given stay, and `remove_reaction` works as before.
- **Check order:** the switch is checked after the permission, as part of it, and like the permission it is read again from the `space` row inside the writer job that commits the change (§ 6.9), so an `update_space` committed just before cannot be slipped past.

**Lobby on connect.** Right after a `Welcome` is queued (an `Auth` that gets a snapshot, or a `Redeem`'s), and never after `Resumed`, the core joins the session to `default_voice_channel` when every condition holds:
- `lobby_on_connect` is on and a default is set;
- the session is on minor ≥ 5, over QUIC with datagrams (§ 6.10 "Voice path");
- the account has **no voice presence on any session**. A connecting session never takes voice over from another of the account's sessions; an explicit `join_voice` still does (§ 6.10). The check and the join run in the same serialized step, so two sessions of one account connecting at once never both join;
- the account is **not a bot** (M8, § 6.15). A bot enters voice only through its own `join_voice`, so connecting never puts a bot in voice and its receiving-audio marker appears only when it chooses to listen.

The join:
- **Checks:** it applies every `join_voice` check (§ 6.10) except the rate limit. It takes no `rate_voice_per_min` token, and it never hashes a password: a default channel with a password is joined only by holders of `BYPASS_CHANNEL_PASSWORD`.
- **On failure:** if a check fails or a condition is not met, the session simply stays out of voice. Nothing is sent, and clients show the member as not in voice.
- **On success:** it is an ordinary join. Its `voice_state_updated` gets a `seq` after the snapshot's, and `voice_session` (ephemeral 6) goes to the session; there is no `Ack`, since nothing was asked.

**Starter templates.** `apply_template` adds the template's channels, roles and overwrites, and never removes, renames or moves anything.
- **One commit:** everything is added in one commit, or nothing is.
- **Placement:** new channels go after the existing siblings, and new roles directly below the actor's highest role, in the order listed (the owner's: at the top).
- **Limits:** it is `CONFLICT` when the result would pass a § 6.8 limit (500 channels, 250 roles, 5,000 overwrites).
- **Duplicate names:** names need not be unique (§ 6.8), so applying a template twice adds a second set. That is documented, not refused; clients warn before re-applying.
- **Default channel:** a template with a lobby sets `default_voice_channel` to it when none is set and the actor holds `MANAGE_SPACE`, in the same commit; without `MANAGE_SPACE` that step is skipped and the rest still applies.
- **Deny bits:** the deny side of a template's overwrites is not checked against the actor. It only takes rights away on channels the same commit creates, so it can grant nothing (as § 6.8's stated exception for taking a role away).
- **Events:** each object gets its § 6.3 event (`channel_created` with its `channel_permissions`, `role_created`, `overwrite_set`, and `space_updated` for the default).

The contents:

| Template | Channels (indent = child) | Roles (highest first) |
|---|---|---|
| `GAMING` | voice `Lobby` (the lobby) · voice `AFK` · category `Games`: voice `Game Room 1` (voice `Squad 1`, `Squad 2`), voice `Game Room 2` (voice `Squad 1`, `Squad 2`) | `Admin` (`ADMINISTRATOR`, hoisted, talk power 100) · `Member` (no extra permissions) |
| `COMMUNITY` | category `Information`: text `announcements`, text `rules` · category `Community`: text `general`, text `help` · category `Voice`: voice `Voice 1`, voice `Voice 2` | `Moderator` (`MANAGE_MESSAGES`, `MANAGE_THREADS`, `KICK_MEMBERS`, `TIMEOUT_MEMBERS`, `MUTE_MEMBERS`, `DEAFEN_MEMBERS`, `MOVE_MEMBERS`; hoisted, talk power 50) |
| `SMALL_TEAM` | text `general` · text `planning` · text `random` · voice `Stand-up` | none |

In `COMMUNITY`, `announcements` and `rules` carry two overwrites:
- `@everyone` denies `SEND_MESSAGES` and `CREATE_THREADS`;
- `Moderator` allows `SEND_MESSAGES`.

`COMMUNITY` and `SMALL_TEAM` have no lobby.

**Minor 5** (§ 6.7):
- **Refused for minor 4:**
  - A minor-4 session's `apply_template` and its `update_space` carrying any field 4–10 are `INVALID`.
  - Its `create_channel` or `update_channel` that sets `slowmode_secs`, `retention_days` or `no_history` on a voice channel stays `INVALID`.
- **What a minor-4 session ignores:** the new `Space` and `SpacePublicInfo` fields, and a voice channel's `slowmode_secs`, `retention_days` and `no_history`, which a minor-5 manager may set and which mean nothing to a client without chat there.
- **No voice-channel chat for minor 4:** a minor-4 client was built on "voice channels have no chat", so a minor-4 session is sent none of it:
  - no message, reaction, pin or thread events of a voice channel;
  - no typing in one;
  - no read state for one;
  - no search hit in one.

  Its message commands and requests on a voice channel stay `NOT_FOUND`, their existing meaning.
- **No lobby join for minor 4:** a minor-4 session is never joined to the lobby.

**Limits:** none beyond § 6.8's. A template is at most 9 channels, 2 roles and 4 overwrites, so its events fit any session's outbound queue (each `channel_created` takes two slots, § 6.3).

### 6.12 Moderation (M6)

Kick, ban, unban and timeout as commands; the audit log and the ban list as requests; and the reason a removal carries. The operator's side (the HTTP API, the operator CLI, backup, export and erasure) is § 6.13. The exact messages and numbers are `yapsta.proto`; this section fixes them first, with § 6.8's conventions.

Moderation carries **no free text** in M6: no reason string, no note. Audit entries, close frames and `Error.message` hold ids, enums, numbers and times only (§ 7.1, § 7.6). A text reason can be added later, add-only. Bans are by identity (`account_id`) only; IP bans are an open question (§ 12.5).

**Objects**
```
enum MemberRemovedReason{UNSPECIFIED = 0, TRANSFERRED = 1, KICKED = 2, BANNED = 3}
enum ActorKind{UNSPECIFIED = 0, MEMBER = 1, OPERATOR = 2}
enum AuditAction{UNSPECIFIED = 0, TRANSFER_MEMBER = 1, TRANSFER_OWNERSHIP = 2, KICK = 3, BAN = 4, UNBAN = 5,
                 TIMEOUT_SET = 6, TIMEOUT_CLEAR = 7, EXPORT = 8, ERASE = 9, BACKUP = 10, RESTORE = 11,
                 ADMIN_TOKEN_CREATE = 12, ADMIN_TOKEN_REVOKE = 13, RESET_OWNER = 14}   (M7 adds 15–16, § 6.14; M8 adds 17–21, § 6.15; M9 adds 22–37, § 6.16)
AuditEntry{id: u64 = 1, at: u64 = 2, actor_kind: ActorKind = 3, actor_account_id: optional u64 = 4,
           action: AuditAction = 5, target_account_id: optional u64 = 6, other_account_id: optional u64 = 7,
           value: optional u64 = 8}
Ban{account_id: u64 = 1, created_at: u64 = 2}
Member gains: timeout_until: optional u64 = 9
MemberRemoved gains: reason: MemberRemovedReason = 2
```
- **`MemberRemoved.reason`:** `TRANSFERRED` for a member transfer (§ 6.8), `KICKED` for a kick and for an erasure (§ 6.13), `BANNED` for a ban. An M6 server never sends `UNSPECIFIED`. A client treats `UNSPECIFIED` or a value it does not know as "removed", reason unknown.
- **`Member.timeout_until`:** present while the member's `timeout_until` (§ 7.1) is in the future, absent otherwise. A freshly built message never carries a past timeout, but a replayed event (§ 6.3) may carry one that has expired since; clients compare it with their clock. It is in both forms (§ 6.8), so it travels in the snapshot, `resync`, `member_page`, `get_member` and `member_updated`. It is computed when the message is built. An expiry changes no row and publishes nothing.
- **`AuditEntry`:** `actor_account_id` is set exactly when `actor_kind` is `MEMBER`. `OPERATOR` is the operator CLI or the HTTP API (§ 6.13), which act for no account. No entry has a string field. What each action fills:

  | Action | Actor | `target_account_id` | `other_account_id` | `value` |
  |---|---|---|---|---|
  | `TRANSFER_MEMBER` | member (the owner) | `from` | `to` | — |
  | `TRANSFER_OWNERSHIP` | member (the owner) | the new owner | — | — |
  | `KICK`, `BAN`, `UNBAN` | member or operator | the account | — | — |
  | `TIMEOUT_SET` | member or operator | the member | — | seconds from the commit to `until` |
  | `TIMEOUT_CLEAR` | member or operator | the member | — | — |
  | `EXPORT`, `ERASE` | operator | the account | — | — |
  | `BACKUP`, `RESTORE` | operator | — | — | — |
  | `ADMIN_TOKEN_CREATE`, `ADMIN_TOKEN_REVOKE` | operator | — | — | the token id (§ 6.13): its 8 bytes read as a big-endian 64-bit integer, stored signed (two's complement, as § 7.1 stores permission bitfields) and carried as that `u64` on the wire; the API renders it as the token id's hex string |
  | `RESET_OWNER` | operator | the former owner | — | — |
  | `JOIN_POLICY_CHANGED` (M7) | member or operator | — | — | the `JoinPolicy` number after the change (§ 6.14) |
  | `OPEN_JOIN_ROLES_CHANGED` (M7) | member or operator | — | — | — |
  | `BOT_CREATE`, `BOT_ROTATE`, `BOT_DELETE` (M8) | member or operator (create: member only) | the bot's account | — | — |
  | `WEBHOOK_CREATE`, `WEBHOOK_DELETE` (M8) | member or operator (create: member only) | — | — | the webhook's id (§ 6.15) |
  | `ROLE_CREATE`, `ROLE_UPDATE`, `ROLE_MOVE`, `ROLE_DELETE` (M9) | member | — | — | the role's id |
  | `MEMBER_ROLE_ADD`, `MEMBER_ROLE_REMOVE` (M9) | member | the member | — | the role's id |
  | `OVERWRITE_SET`, `OVERWRITE_DELETE` (M9) | member | the account, for a member overwrite | — | the role's id, for a role overwrite; the overwrite's channel is never recorded |
  | `CHANNEL_CREATE`, `CHANNEL_UPDATE`, `CHANNEL_MOVE`, `CHANNEL_DELETE` (M9) | member | — | — | — |
  | `INVITE_CREATE`, `INVITE_REVOKE` (M9) | member or operator (create: member only; the operator revokes in a restore, § 7.5, M12) | — | — | the invite's id |
  | `THREAD_DELETE` (M9) | member | the thread's creator | — | — |
  | `TEMPLATE_APPLY` (M9) | member | — | — | the `StarterTemplate` number |

**Commands** (§ 6.8 numbering rules continue; replies as there):

| # | Kind | Fields | Allowed for | Reply |
|---|---|---|---|---|
| 51 | `kick_member` | `account_id` | `KICK_MEMBERS`; the target ranked below the actor | `Ack` |
| 52 | `ban_member` | `account_id` | `BAN_MEMBERS`; the target ranked below the actor | `Ack` |
| 53 | `unban_member` | `account_id` | `BAN_MEMBERS` | `Ack` |
| 54 | `timeout_member` | `account_id`, `until?` (absent clears) | `TIMEOUT_MEMBERS`; the target ranked below the actor | `Ack` |

Their messages are `KickMember{account_id: u64 = 1}`, `BanMember{account_id: u64 = 1}`, `UnbanMember{account_id: u64 = 1}` and `TimeoutMember{account_id: u64 = 1, until: optional u64 = 2}`. The permissions are checked in the base permissions (§ 8.2 step 1): they are space-wide. There are no new `CommandResult`, event, ephemeral or `ErrorCode` kinds: `member_updated` and `member_removed` carry every change.

**Requests** (§ 6.8; request messages named `<Kind>Request` in CamelCase):

| # | Kind | Fields | Allowed for | Reply (`Response.kind`) |
|---|---|---|---|---|
| 13 | `audit_page` | `before?`, `limit` (1–100), `action?: AuditAction` | `VIEW_AUDIT_LOG` | `audit_page` (newest first) |
| 14 | `ban_list` | `before?`, `limit` (1–100) | `BAN_MEMBERS` | `ban_page` (by descending `account_id`) |

`Response.kind` adds `audit_page: AuditPage{entries: repeated AuditEntry = 1, has_more: bool = 2} = 8` and `ban_page: BanPage{bans: repeated Ban = 1, has_more: bool = 2} = 9`.
- `audit_page` returns the entries with `id` below `before` (absent: from the newest) with that `action`, when one is given. An `action` of `UNSPECIFIED` or a value outside the enum is `INVALID`.
- `ban_list` returns the bans with `account_id` below `before` (absent: from the highest).
- Both read through the reader pool, never the writer. Each reserves 1 KiB × `limit` (§ 6.1), as `member_page` does.
- Every entry is visible to every holder of `VIEW_AUDIT_LOG`: entries carry account ids only, never a channel or anything that follows `VIEW_CHANNEL`. The M9 management actions (§ 6.16) keep to this: a role's id goes in `value`, an account in `target_account_id`, and a channel (an overwrite's, a thread's, a changed one's) is never named; an invite's id is named, since invites are space-wide.

**Rules**
- **Check order** is § 6.8's:
  1. `NOT_FOUND`. For `kick_member` and `timeout_member`, the target is not a member. For `ban_member`, the space has never known the account (no `accounts` row); a former member can be banned. For `unban_member`, the account is not banned. A ban is visible only to holders of `BAN_MEMBERS`, so for anyone else `unban_member` is `NOT_FOUND` whether or not the ban exists.
  2. `FORBIDDEN`: the permission, then the hierarchy (§ 6.8). The target must rank strictly below the actor. **The owner is never a target**, for every actor, the operator included. `ADMINISTRATOR` passes the permission check but not the hierarchy. **Acting on oneself is `FORBIDDEN`:** an actor does not rank below themself, and unlike `set_nickname` and `move_member` there is no "or the actor themself". This differs from § 6.8's member transfer, where naming one account twice is `INVALID`: there both ids are values of one command; here the actor is not a valid target. A non-member target of `ban_member` has rank 0.
  3. `INVALID`: `until` at or before now, or more than 28 days (2,419,200 s) after now.
  4. Nothing is `CONFLICT`. Banning an account that is already banned, and clearing a timeout that is not set, are acknowledged without a change, an event or an audit entry. Setting a timeout always replaces the stored one and is audited.
- **The operator** (§ 6.13) runs the same checks and the same writer jobs as a member, with no account. It passes every permission and hierarchy check except the rule above: the owner is never a target.
- **Kick and ban follow the member transfer flow** (§ 6.8):
  - **One transaction:** the `bans` row (ban only), the membership (the `members` row with its nickname, profile and timeout; its `member_roles`; its read states), the avatar's attachment row, and the audit entry. From M8 also the webhooks the account created (as `transfer_member` deletes those of its `from`) and, for a bot, its `bots` row (§ 6.15). From M9 also the **grants** of the channel overwrites naming the account: each member overwrite loses its `allow` bits and keeps its `deny` bits (a channel mute survives a kick and a rejoin); one left with no `deny` is deleted. Each change is published after the commit as `overwrite_set` or `overwrite_deleted`. And, except for `transfer_member` (the same person, recovering), each bot it created gets a fresh key no one holds: its `bot_pub` is replaced by the public key of an Ed25519 key pair generated from the OS RNG whose secret is dropped at once, its sessions are closed with `UNAUTHENTICATED` (as after `rotate_bot`), the webhooks the bot created are deleted (their tokens may be the creator's), and it is kept with its roles and commands; the owner, or the operator through the admin API, brings it back with `rotate_bot` (§ 6.15, § 6.16).
  - **One apply step**, before the commit's events are published: every session of the account leaves voice (§ 6.10 "Evictions": the membership ended), is closed with `MEMBER_REMOVED`, and has its resume tokens dropped (§ 6.2).
  - **Then** `member_removed{account_id, reason}` is published to every member. It is a visibility change for resume (§ 6.3).
  - **DMs (M10):** the same transaction applies § 6.17 "Membership" (group DMs left, DM read states deleted, 1:1 DMs kept for the other side).
  - **What stays:** invites the account created stop working, as for any creator who is not a member, and work again if it rejoins and holds `CREATE_INVITES` (§ 6.8). From M9 overwrites naming the account keep only their denies (above), so a rejoin gets back no channel grant. Its messages, reactions, threads and pins stay; removing them is erasure (§ 6.13).
- **After a kick** the account is a non-member: its next `Auth` gets a non-member `Welcome`, and it may redeem a new invite.
- **After a ban**, `Auth` still works and gets a non-member `Welcome` (the public info only). `Redeem` is `FORBIDDEN` before the code is looked at (§ 6.2 "Bans first"), and again inside the transaction that would create the membership. A ban committed while a `Redeem` waits for the writer therefore still holds; the ban and the removal commit together, so no `Redeem` slips in between.
- **`unban_member`** deletes the `bans` row and writes the audit entry; it publishes nothing. It does not restore the membership: the account needs a new invite.
- **Timeout:** `timeout_member` writes `members.timeout_until` (`until`, or null to clear) and the audit entry, then publishes `member_updated` (full form) to every member.
  - **Chat:** the § 6.9 refusals (send, edit, react, create threads, poke, typing; from M9 also `update_thread`, `update_profile`, `set_avatar` and one's own `set_nickname`) apply from the commit. The writer job reads the row (§ 6.9).
  - **Voice:** a timed-out member is not forwarded on either route, and may still join and listen (§ 6.10 "Who is heard", "Whisper"). Routes are rebuilt in the apply step of every set and clear, before `member_updated` is published.
  - **Expiry:** the hub keeps every member's stored `timeout_until` in memory (loaded at startup, changed in apply steps) and judges it by the wall clock, as the store does, so a clock step or a suspended host never splits voice from chat. One timer wakes it when the soonest ends, and at least once a second while any is kept. A pass re-judges each timeout by the wall clock and rebuilds the routes of the channels of the accounts whose timeout ended, or ran again after the clock stepped back, so forwarding follows within a second with no client action. Messages built in between already leave a passed one out. An ended timeout is kept for an hour after its `until` (`TIMEOUT_GRACE`), so a clock stepped back before it brings it back in voice as in chat; one stepped back later than that is caught at the next restart, which loads the stored value. Datagrams are never checked against the clock one by one (§ 6.4).
  - The voice side was specified in M4 and not enforced; this resolves #154.
  - An expired value stays in the row and means nothing. A kick or ban removes it with the membership, and a member who rejoins starts without one.
- **Member transfer** (§ 6.8) sets `reason = TRANSFERRED` from M6; nothing else about it changes.

**Minor 6** (§ 6.7):
- An M6 server sends `Hello.versions = [6, 5]`, so a minor-4 client gets `UNSUPPORTED_VERSION`.
- A minor-5 session's commands 51–54 and requests 13–14 are `INVALID`.
- A minor-5 session ignores `Member.timeout_until` and `MemberRemoved.reason`. A kicked or banned minor-5 session is closed with `MEMBER_REMOVED`, as before; its client reads every removal as before.

**Limits:**
- There is no count limit on bans: each is one row of ids.
- Moderation commands take no rate-limit token. Each changes at most one member, and its events are bounded like any § 6.8 command's.

### 6.13 Administration (M6)

The operator runs an instance with the HTTP admin API, `/metrics`, the web panel and the operator CLI, never through a member's identity. Everything the operator does is audited with `ActorKind.OPERATOR` (§ 6.12), except `status`.

**Listener**
- **One listener.** The API, `/metrics` and the panel share the § 6.5 HTTPS listener on 7121 (`https_listen`). `crates/net` (`https.rs`) keeps owning every connection, so these still apply to the admin paths:
  - TLS 1.3 and ALPN;
  - `HEADER_TIMEOUT` and the handshake timeout;
  - the idle timeout;
  - the per-address and total connection caps;
  - the progress floor on bodies.
- **Routing:** requests under `/files/` and `/uploads/` are served by `crates/net` as in § 6.5, and from M8 `/webhooks` and `/webhooks/…` (§ 6.15). Every other request is handed to one `tower::Service` injected at startup.
- **Crates:** `crates/admin` builds that service: an axum `Router` with `/api/v1/…`, `/metrics` and the panel at `/`. It reaches the space core through an operator handle `crates/net` exposes, which runs the same commands and reads as a session does, with the operator actor. `crates/admin` depends on `crates/net`, and `crates/server` wires them together.
- **When it is off:** with `https_listen` off there is no API, metrics or panel. With `admin_api` off (§ 5) no service is injected, and every path but the file and webhook routes is 404, as in M3.
- **Logs:** no path logging for `/files`, `/uploads` and `/webhooks` (§ 6.5, § 6.15). The API logs the method, the route template (axum's `MatchedPath`) and the status, never the raw URI, a query, a header or the peer address.

**Authentication**
- **Token format:** `Authorization: Bearer <id>.<secret>`; the scheme is matched in any case (RFC 9110 § 11.1), as on `POST /webhooks`.
  - `id`: 8 bytes from the OS RNG as 16 lowercase hex characters. A non-secret lookup key, shown by `admin-token list`.
  - `secret`: 16 bytes (128 bits) from the OS RNG as 26 lowercase RFC 4648 base32 characters without padding.
- **Storage:** `admin_tokens` (§ 7.1) stores the id and an argon2id PHC hash of the secret, with the claim code's parameters (§ 6.2, § 7.6). The token is shown once, by `admin-token create`; nothing else ever prints it.
- **Managing tokens:** CLI only (`yapsta-server admin-token create|list|revoke`), so a stolen token cannot mint more. The commands work while the server runs ("Beside a running server" below): each is one short `BEGIN IMMEDIATE` transaction (the token row and its audit entry). `revoke` sets `revoked_at` and takes effect on the next request.
- **Per request, in order:**
  1. **Cache first (M9).** A well-formed token whose id is in the cache (step 3) and whose secret's SHA-256 matches the cached digest is checked against the database (step 2) and, unless revoked, authenticated without touching the failure bucket: one SHA-256, so a valid token is never throttled by others sharing its address, behind a proxy or CGNAT (§ 6.16). Every other request goes on to step 1a.
  1a. **Rate limit.** A request with a missing, malformed, unknown or revoked token, or a wrong secret, is a failed auth. Every request that step 1 did not authenticate takes a token from its address key's bucket (`rate_auth_fail_per_min`, a bucket of its own beside `Auth`'s, § 9) before any further lookup or hash, and gets it back on success. An empty bucket is `429` with `Retry-After`. From M12 (#433), when its address's bucket is empty, a request naming a live (unrevoked) token takes from that token's own bucket instead, at the same `rate_auth_fail_per_min`, with the same refunds, so a neighbour sharing the admin's address cannot keep a token whose digest is not yet cached (after a restart, or a new token) from ever being verified. Whether an id is live is read from a snapshot of the live ids, read again only for an id not in it and at most once a second whatever the load (a failed read counts; the read runs in a task of its own, so a request dropped mid-read, such as a reset stream, still leaves the snapshot filled; and a request whose id is not in the snapshot while a read runs waits for that read), so this path adds at most one read a second; an id not in the snapshot is `429` with no bucket or hash, and the row is still read before any hash (step 2). A token revoked while in the snapshot costs one bucket token and that row read, no hash, before it is forgotten; a revoked token whose digest is cached is forgotten at step 1. Accepted: on an empty address bucket a live id answers differently from an unknown one (a hashed `401` against an immediate `429`), which tells only someone who already holds the id; and a token's id is not secret to everyone (it is the `value` of the `ADMIN_TOKEN_*` audit entries, which members with `VIEW_AUDIT_LOG` read, § 6.12), so anyone holding the id can drain that token's bucket from any address. Locking the admin out still needs the admin's address bucket drained as well, that is, a neighbour who also holds the id: the bound is the operator's rate per live token, and hiding token ids from members is separate work.
  2. **Lookup:** the id is looked up through the reader pool on every request. An unknown or revoked id is `401` without hashing, and drops the id's cache entry (below), so a revocation takes effect on the next request.
  3. **Verify from the cache:** after the first successful argon2id verification of a token, the server keeps id → SHA-256(secret) in memory, never on disk. A request whose secret's SHA-256 equals the cached one (constant-time comparison) is authenticated with no argon2. From M9 a request that waited on a shared first verification (step 4) and whose secret does not match the digest it cached is `401` without hashing; only when the shared verification failed does a waiter verify again, through the same single flight. The cached digest and the secret parsed from the request are zeroizing values that are never `Debug`-formatted or logged (§ 7.6). A mismatch leaves the cache entry as it is.
  4. **Verify with argon2id:** on a cache miss or a mismatch, the secret is verified against the stored PHC hash in `crates/net`'s redeem `HashPool`, which `Redeem` and channel passwords share (§ 6.2, § 6.8: at most 2 hashes at once; `Auth` does no argon2). Admin verifications pass their own admission first (from M8 one place shared with webhook posts, § 6.15): one running or waiting at a time. From M9 concurrent first uses of one token id wait for a single verification, so one id never costs two hashes at once; they share only the digest it puts in the cache, never its result: each waiter then compares the SHA-256 of its own secret with that digest (step 3), so a wrong secret is never accepted beside a right one, and a right one is verified again if the shared verification failed. Past it the request is `503` with `Retry-After`, and its rate-limit token is given back. So the API cannot starve `Redeem` or channel passwords. A wrong secret is `401`; a right one fills the cache.
- **Coverage:** one auth layer covers every `/api/v1` route and `/metrics`, including `/api/v1/openapi.json` (OpenAPI 3.1, behind auth). Only the panel's static assets are public.
- **Unknown paths:** an unknown path under `/api/` is a JSON `404`, whether or not authenticated; the auth layer runs first only on routes that exist. A route that exists asked with another method is a JSON `405`, also before auth (a `401` would tell as much: that the path exists).
- **Behind a reverse proxy,** every request comes from the proxy's address, so the failed-auth bucket is shared by all its clients. That is accepted for an admin surface: from M9 a token already verified since the server started is never charged (step 1), and `X-Forwarded-For` is still never read.

**Responses**
- **Headers on every response** from the admin service (API, metrics, panel):
  - `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`;
  - `X-Content-Type-Options: nosniff`;
  - `Referrer-Policy: no-referrer`;
  - from M9, `Strict-Transport-Security: max-age=31536000` (on the file routes too, § 6.5). A browser keeps it only once it trusts the certificate, so it protects a CA-certified proxy or certificate and costs a self-signed one nothing.

  API responses also carry `Cache-Control: no-store`. There are no CORS headers, so no other origin's page can read a response.
- **Certificate fingerprint (M9):** a browser cannot pin the server's key as Yapsta clients do, so `run` logs the SHA-256 fingerprint of the certificate the 7121 listener serves at every start, and `yapsta-server tls-fingerprint` prints it, as colon-separated uppercase hex pairs, the form browsers show. It is public data. An operator who exposes the panel compares it before trusting the certificate, or puts a CA-certified reverse proxy in front, or sets `admin_api = off` (§ 6.16).
- **Bodies:** requests are limited to 1 MiB unless a route says otherwise (`413` past it). API bodies are JSON. Ids and times are JSON numbers, and token ids are hex strings.
- **Errors:** a fixed body `{"code": "<code>", "message": "<fixed text>"}`, never with user text or an id.

  | Status | `code` |
  |---|---|
  | 400 | `invalid` |
  | 401 | `unauthenticated` |
  | 403 | `forbidden` |
  | 404 | `not_found` |
  | 405 | `method_not_allowed` |
  | 409 | `conflict` |
  | 409 | `backup_dir_unusable` (only `POST /api/v1/backup`: `backup_dir` cannot be written; no `Retry-After`, #241) |
  | 413 | `too_large` |
  | 429 | `rate_limited` |
  | 503 | `unavailable` |

  A command's `ErrorCode` maps to the row of the same name.

**Routes** (all under auth; each is in the OpenAPI document):

| Method | Path | What | Notes |
|---|---|---|---|
| GET | `/api/v1/openapi.json` | The OpenAPI 3.1 document | |
| GET | `/api/v1/status` | Version, uptime, schema version, members, sessions, voice sessions, database and blob bytes, last backup time | Counts and sizes only |
| GET | `/api/v1/members` | Members in snapshot form (§ 6.8), with `timeout_until` | `?after=<account_id>&limit=1–100`, ascending |
| POST | `/api/v1/members/{id}/kick` | `kick_member` | `204` |
| POST | `/api/v1/members/{id}/ban` | `ban_member` | `204` |
| POST | `/api/v1/members/{id}/timeout` | `timeout_member` | Body `{"until": <unix seconds> \| null}`; `204` |
| GET | `/api/v1/bans` | The ban list | `?before=<account_id>&limit=1–100` |
| DELETE | `/api/v1/bans/{id}` | `unban_member` | `204` |
| GET | `/api/v1/audit` | Audit entries, newest first | `?before=&limit=1–100&action=<name>`; actions by their stored names (§ 7.1: `kick`, `timeout_set`, …, as `yapsta-cli audit --action` takes them; `unknown` for one this server does not know); the token actions' `value` as the token id's hex string |
| POST | `/api/v1/backup` | A backup into `backup_dir` (§ 7.5) | `202` with `{"name": "yapsta-backup-<unix seconds>"}`; `409` while one runs, when `backup_dir` is unset, or when this second's directory already exists (`conflict`); `409` `backup_dir_unusable` when `backup_dir` cannot be written: a file on its way, a directory the server cannot search or make into, or a place inside the data directory's `blobs/`, `secrets/` or `tls/` (one warning with the error's kind, never the path; no `Retry-After`, as waiting fixes nothing); `503` only when the backup's task cannot run. It runs in the background; its `BACKUP` audit entry and `status` show when it is done; a failure is logged as its kind only |
| POST | `/api/v1/members/{id}/export` | The account's export (below) | `200`, `application/zip`, `Content-Disposition: attachment`; the response size has no limit |
| POST | `/api/v1/members/{id}/erase` | Erasure (below) | `202`; the erasure runs in writer jobs after the reply |
| GET, PATCH | `/api/v1/space/join-policy` | The join policy and open-join roles (M7) | § 6.14 |
| GET | `/api/v1/roles` | The roles, for the join-policy picker (M7) | § 6.14 |
| GET | `/api/v1/bots`, `/api/v1/webhooks` | Bots and webhooks (M8) | § 6.15 |
| POST | `/api/v1/bots/{id}/rotate` | A new bot seed, shown once (M8) | § 6.15 |
| DELETE | `/api/v1/bots/{id}`, `/api/v1/webhooks/{id}` | Delete a bot or a webhook (M8) | § 6.15 |

- **Pages:** `GET /api/v1/members` is `{"members": [...], "has_more"}` with each member as `account_id`, `joined_at`, `nickname`, `role_ids`, `display_name`, `avatar_id` and `timeout_until` (the snapshot form, so it carries names; from M7 `GET /api/v1/roles` carries role names too, § 6.14, and from M8 `GET /api/v1/bots` and `GET /api/v1/webhooks` carry bot and webhook names, § 6.15; every other route carries ids, numbers and times only). `GET /api/v1/bans` is `{"bans": [{"account_id", "created_at"}], "has_more"}`. `GET /api/v1/audit` is `{"entries": [...], "has_more"}` with each entry as `id`, `at`, `actor` (`member` or `operator`), `actor_account_id`, `action`, `target_account_id`, `other_account_id` and `value`. `limit` is required. A path, query or body the route cannot read is `400 invalid`; a body past the cap stays `413`.
- **One code path:** actions through the API use the same core as the protocol commands (§ 6.12), with the operator actor. There is no second implementation of the teardown.
- **Never a target:** the owner, for every route that removes or restricts (kick, ban, timeout, erase), which is `403`. Exporting the owner is allowed (Export, below).

**Metrics**
- **Endpoint:** `GET /metrics` serves the Prometheus text format 0.0.4 (`text/plain; version=0.0.4`), behind auth. It exists only when the `metrics` key is on (§ 5; default off); otherwise it is `404`.
- **Families:**

  | Name | Type | Labels |
  |---|---|---|
  | `yapsta_sessions` | gauge | `transport` (`quic`, `tcp`) |
  | `yapsta_members` | gauge | — |
  | `yapsta_voice_sessions` | gauge | — |
  | `yapsta_voice_frames_forwarded_total` | counter | — |
  | `yapsta_commands_total` | counter | `kind` (the command kind's name), `result` (`ok` or the `ErrorCode` name) |
  | `yapsta_http_requests_total` | counter | `route` (template), `status` |
  | `yapsta_refusals_total` (M9) | counter | `reason`: `non_member_cap`, `non_member_deadline`, `partial_frame`, `media_over_bitrate` (a track ended over its bitrate cap, § 6.6), `voice_byte_rate` (voice datagrams dropped over a sending session's byte rate, § 6.10), and the reasons later M9 limits add (§ 6.16) |
  | `yapsta_writer_queue_depth` | gauge | — |

- **Labels** are route templates, status codes and enum names only. Never an id, a token id, a raw URI or an address (§ 7.6). A request no route matched is counted under `route="unmatched"`.
- **What is counted:**
  - **Sessions:** member sessions, by the transport they came in on. A non-member's session before its `Redeem` is not one of the space's.
  - **Commands:** the commands a session runs, by kind (the kind's field name in `Command.kind`, e.g. `get_space`) and result (`ok`, or the `ErrorCode` name, e.g. `ERROR_CODE_FORBIDDEN`). Not counted: frames refused before they run (a kind newer than the session's minor, a non-member's command, a second `fetch_space_icon`), and the operator's actions over the API (counted as HTTP requests).
  - **HTTP:** every response on the 7121 listener, the admin service's by its route template and the file routes as `/files/{id}` and `/uploads/{id}`.
  - **Voice frames:** one per copy sent to a listener.
  - **Writer queue:** jobs waiting, not the batch the writer is running.
- **Process-wide counters:** the counters start at 0 when the server starts; the gauges are read at the scrape. No metrics crate: there are counters and gauges only.
- **Not in the API's OpenAPI document:** `/metrics` is behind the same auth layer, and a scrape is never cached (`Cache-Control: no-store`).

**Panel**
- **Build:** `web/` (React + Vite + TypeScript, as ts3-bot, § 5), built to `web/dist` and embedded in the binary. A build without `web/dist` serves an empty page.
- **Serving:** at `/`, with `index.html` for `GET` on the panel's own routes (deep links: `/`, `/members`, `/bans`, `/bots`, `/hooks` (the Webhooks page: `/webhooks` itself is the inbound webhook route, § 6.15, #469), `/audit`, `/backup`, matched exactly on the raw path; `web/src/panel-routes.test.ts` keeps the list equal to `web/src/router.tsx`). Any other path that is not a file of the build, and every other method, is `404` (#463).
- **Token:** the operator enters an admin token. The panel holds it in memory only and asks again after a reload: no cookie, no browser storage. So there is no CSRF surface.
- **Talks only to `/api/v1`.** It renders every name and text as a text node, never as HTML. It makes no third-party request: no external font, script or image. The build emits no inline script or style (the CSP forbids them).
- **Pages:**
  - status, from M7 with the join-policy setting (§ 6.14);
  - members, with kick, ban and timeout, each behind a confirmation;
  - bans, with unban;
  - audit (paged, filters);
  - backup.

  Export and erasure are CLI and API only in M6.

**Operator CLI** (`yapsta-server <command>`; parsed by hand like `init` and `claim-code`):
- **Data-directory lock:** from M6, `run` holds an exclusive lock on `yapsta.lock` in the data directory (`std::fs::File::try_lock`) for its lifetime. "Server stopped" below means the command takes that lock and refuses, exiting non-zero and changing nothing, while it is held. `claim-code` (§ 6.2) and `init` take it too, so a mistaken run beside the server is refused instead of trusted to the operator. `run --init-if-needed` takes it once, before deciding whether to `init`, and holds it through `init` and `run`. `status` takes it for an instant to see whether the server runs (held: running) and drops it before reading; every command that takes it to hold it tries again three times, 100 ms apart, before refusing, so a `run` started during a `status` is not refused.

| Command | Server | What | Audited |
|---|---|---|---|
| `status` | either | Running or not (the lock: held by `run`, or by a command that needs the server stopped), version, schema version, data directory, member and channel counts, database and blob sizes, last backup time. No names, no content. After a restore left part-way (§ 7.5) it refuses, as `run` does; while a restore runs it says so | no |
| `backup <dir>` | stopped | § 7.5. A live backup is `POST /api/v1/backup` into `backup_dir` | `BACKUP` |
| `restore <dir>` | stopped | § 7.5 | `RESTORE` (written into the restored database) |
| `reset-owner` | stopped | Clears `space.owner_account_id` and issues a new claim code (§ 6.2). The former owner stays a member and keeps its roles. With no owner, invites stop working until the claim code is redeemed (only the claim code can be redeemed while the space is unclaimed, § 6.2), and an existing member may redeem it to become the owner. It prints the code and these next steps. The owner unset, the `RESET_OWNER` entry and the new claim are one transaction; with no owner to clear it changes nothing and exits non-zero (`claim-code` issues a code then) | `RESET_OWNER` |
| `admin-token create` | either | Prints the new token once | `ADMIN_TOKEN_CREATE` |
| `admin-token list` | either | Id, creation and revocation times. Never a hash | no |
| `admin-token revoke <id>` | either | Revokes; an unknown id exits non-zero | `ADMIN_TOKEN_REVOKE` |
| `export <account_id> <file>` | either | The export below, to a new file | `EXPORT` |
| `erase <account_id>` | stopped | Erasure below: the CLI itself removes the member, runs every batch and the final `wal_checkpoint(TRUNCATE)`. While the server runs, use `POST /api/v1/members/{id}/erase`, which also closes the account's sessions and queues the batches for housekeeping | `ERASE` |

- **Beside a running server:** only `status`, `export` and `admin-token create|list|revoke` run while the server holds `yapsta.lock`.
  - They never go through `Store::open`: no migration, no `optimize`, no journal-mode change.
  - `status` reads, and `export` reads its data, on a read-only connection. `admin-token` and `export` each use one plain write connection for their only writes: single-row transactions on `admin_tokens` and `audit_log` (`export`'s one `EXPORT` entry), tables whose only in-memory state in the server, the token cache, these writes cannot make stale: Authentication step 2 re-checks the row on every request.
  - These connections take the server's hardened options (`trusted_schema = OFF`, no extension loading, `foreign_keys` on) and a `busy_timeout`, so a `BEGIN IMMEDIATE` beside the live writer waits instead of failing with `SQLITE_BUSY`.
  - Each refuses, changing nothing, unless the database's applied migrations equal the binary's exactly.
  - Only commands holding `yapsta.lock` may use the normal open, which migrates. Every other command needs the server stopped, as `claim-code` does.
- **Output:** the CLI prints ids, counts and times, never names or content.

**Export** (GDPR Art. 20)
- **Format:** a zip of JSON files:
  - `profile.json`: display name, bio, pronouns and the avatar file;
  - `membership.json`: `joined_at`, role ids and nickname;
  - `manifest.json`: the export time, the account id, and each attachment listed as removed (below) by `attachment_id` and `message_id` only (from M10 with `dm_id` for a DM message's); no file names, nothing of other members (§ 7.6);
  - `messages.json`: every message the account authored, tombstones excluded, each with `id`, `channel_id`, `thread_id`, `created_at`, `edited_at`, `content` and `reply_to`;
  - from M10 `dm_messages.json`: every DM message the account authored (§ 6.17), tombstones excluded, each with `dm_id`, `id`, `created_at`, `edited_at`, `content` and `reply_to`; and `dms.json`: each DM the account is a member of, by `dm_id` and `kind` only (no other member's id or the group's name); their attachments go under `attachments/` like those of channel messages; and `notification_settings.json`: its settings (target, id, level, mute);
  - `attachments/<attachment_id>`: the files of those messages' attachments, under their media type's extension.

  Nothing from other members goes in (Art. 20(4)): no other author's message, no reaction counts, no names of others.
- **Reading:** the export reads through the reader pool (or a read connection, from the CLI) in pages. A former member gets `messages.json` and attachments only (from M10 also `dm_messages.json`).
- **Files gone meanwhile:** an export takes no blob GC fence. An attachment deleted (by its author, a moderator or retention) after its row is read and swept before its file is copied is no longer the member's data to export: it is listed in `manifest.json` as removed, and the export goes on. An export never fails for it.
- **Writing:** the file is created new with mode 0600; an existing file is refused. The API builds it in a 0600 temporary file in the data directory with a fixed name prefix (`export-tmp-`), streams it, and deletes it; leftovers from a crash are removed at startup. Its contents are never logged.
- **Entries:** the files are `attachments/<attachment_id>.<ext>`, the extension from the stored media type (`bin` for an unknown one); `profile.json`'s `avatar` names the avatar's entry, or is null. Entries are stored uncompressed, mode 0600.
- **One at a time, never half:** the API builds one export at a time; another request meanwhile is `409`. An export that does not finish (an error, a dropped request, a stop) removes its file; the CLI's file stays only once its `EXPORT` entry is written.
- **Not the owner:** exporting the owner is allowed. The owner is never a target only for actions that remove or restrict.

**Erasure** (GDPR Art. 17; § 7.3)
- **Removal first:** if the account is a member, it is removed from the space first, as a kick: the § 6.12 flow with reason `KICKED` and one audit entry, `ERASE` (no `KICK` entry). The owner is never a target. From M8 the queue transaction deletes the webhooks the account created, whether or not it is still a member, and the removal deletes a bot's `bots` row (§ 6.15).
- **Queue:** the same transaction queues the account in `erasures` (§ 7.1). Erasing a queued or former member again is accepted: it records another `ERASE` entry (each is an operator action) and queues the account once. While it is queued, `Redeem` from the account is `FORBIDDEN`, as for a ban, so no new content lands mid-erasure. Through the API, housekeeping works the queue in writer jobs of at most 500 rows each, and after a restart it carries on where it stopped. The CLI's `erase` (server stopped) runs the same batches itself, to the end.
- **What the jobs do**, in this order:
  1. **Messages:** every message the account authored becomes a tombstone as on delete (§ 6.9, § 7.3): content blanked, its FTS entry replaced by the tombstone's empty one (`secure-delete`), its mentions, reactions, pin and attachment rows removed. `author_account_id` is set to null, so the author is "deleted member" (`author_id` 0 on the wire). Tombstones it authored earlier get the null author too.
  2. **Reactions** the account gave on other messages are removed.
  3. **Attachments** it uploaded are removed, pending ones included, except a custom emoji's image and the space icon (below). Erasure deletes no blob file itself: the existing sweep (§ 6.5, § 7.2) removes blobs no attachment references, so a writer job never touches the blob GC fence.
  4. **Thread names** of threads it created are replaced with the fixed name `deleted thread`, so clients of minors 3–5 see nothing new.
  5. **Invites** it created are deleted (with `invite_roles`).
  6. **DMs** (M10): § 6.17 "Membership" applies (it ran with the removal for a member, and runs here for a former one); besides, every DM message it authored becomes a tombstone with a null author, as in step 1, and its DM reactions and its own block list are deleted. Its 1:1 DMs stay for the other side, with its messages as tombstones. Blocks other accounts hold on it, and group names, stay: they belong to the others and the group. The personal ring is redacted as the space ring is (§ 6.3).
- **When it ends:** the `erasures` row is deleted and `PRAGMA wal_checkpoint(TRUNCATE)` runs, waiting up to 2 s for readers as in § 7.2.
- **Resume ring:** it is redacted as the tombstones are made: message events take the tombstone form, the account's reaction events lose their `emoji`, and its `member_joined` and `member_updated` events lose their profile text and nickname, and the `thread_created` and `thread_updated` events of its threads are re-encoded with the name `deleted thread`, each keeping its `seq`.
  The redaction also blanks the emoji of every reaction on the tombstoned messages, as a delete does. A resume whose gap holds the removal's `member_removed` gets a snapshot (§ 6.3), so the redaction keeps the account's text out of the ring's memory rather than out of a replay.
- **Batches:** each job works the first stage with work left, in the order above, at most 500 of its rows (a message's mentions, reactions, pin and attachment rows go with it, as in pruning); every stage is looked at again on every job, so content that landed meanwhile is still taken. The queue has its own housekeeping loop, interleaved with the other passes batch by batch. `reactions`, `threads` and `invites` are indexed by account for it (migration 0013).
- **No events:** erasure publishes nothing per message, as pruning does (§ 7.4). Clients see the tombstones in history, and what they cached before is theirs.
- **What stays:** pseudonymous ids and public keys, and the space's own assets:
  - the `accounts` row and `account_pub`, so a ban outlives erasure and a returning key gets the same `account_id`;
  - the `device_lists` row and its `device_list_entries` (public device keys and expiries only). § 6.2 stores a presented list only when none is stored, so deleting the stored one would let an old signed list, with a device revoked since, be accepted again under the same `account_id`;
  - the `bans` row, if any;
  - audit entries;
  - custom emoji the account created, and the space icon if it uploaded it. They are space assets the member made for the space, not the member's personal data; their attachments' `uploaded_by` stays as a pseudonymous id;
  - pins it made on others' messages;
  - mentions of it in others' messages, which are their authors' content;
  - messages posted through webhooks it created: they are the webhook's, not the member's (§ 6.15), and stay searchable. The webhooks themselves went with the membership (§ 6.12).
  From M9 overwrites naming it keep only their denies, and bots it created have a key no one holds (§ 6.12).
- **Every `NOT NULL REFERENCES accounts` column:**

  | Column | Erasure |
  |---|---|
  | `invites.created_by` | row deleted |
  | `attachments.uploaded_by` | row deleted, except a custom emoji's image and the space icon, which keep the id |
  | `threads.created_by` | id kept, name replaced with `deleted thread` |
  | `reactions.account_id` | row deleted |
  | `pins.pinned_by` | id kept |
  | `read_states.account_id` | row deleted (already at removal) |
  | `emoji.created_by` | id kept |
  | `webhooks.created_by` (M8) | row deleted in the queue transaction, member or not: the account's webhooks stop (§ 6.15) |
  | `bots.account_id` (M8) | row deleted with the removal, when the account is a bot's (§ 6.15) |

  Nullable ones: `messages.author_account_id` becomes null (nullable since M3, § 7.1). `audit_log.actor_account_id`, `target_account_id` and `other_account_id` are kept. `bans.account_id` is kept, and so is `permission_overwrites.account_id` (from M9 such a row holds denies only). `members.account_id` goes with the membership, and `device_lists.account_id` is kept. `space.owner_account_id` never names an erased account. From M8, `bots.created_by` is kept (a pseudonymous id; not a foreign key); from M9 such a bot has been re-keyed (§ 6.12). From M10 (none of these is a foreign key): `dm_messages.author_account_id` becomes null; `dm_reactions.account_id` and `blocks.account_id` go with their rows; `dm_members.account_id` goes for group DMs and is kept for 1:1s, as are `dms.pair_low` and `pair_high`; `dms.owner_account_id` never names an erased account (ownership passed on); `dm_mentions.account_id` and other accounts' `blocks.blocked_account_id` are kept (pseudonymous ids).

  Every `REFERENCES attachments` column:

  | Column | Erasure |
  |---|---|
  | `members.avatar_attachment_id` | the avatar's attachment is removed with the membership, as on any kick |
  | `emoji.image_attachment_id` | kept, with its attachment |
  | `space.icon_attachment_id` | kept, with its attachment |
- **Backups:** backups made before an erasure still hold the erased content, and restoring one brings it back with no `erasures` row. The operator runs `erase` again after such a restore, and should expire old backups.


### 6.14 Open join (M7)

An owner may let anyone who knows the server's address join without an invite (operator, 2026-11-09). New instances stay invite-only (§ 6.2). An open space works as a standing invite of whoever opened it: it reuses the `Redeem` path, so an open join is checked and committed exactly as an invite redemption is, and the rules that keep an invite from granting more than its creator holds (§ 6.8, § 8.1) hold for it too. It has its own rate limit.

**Objects**
```
enum JoinPolicy{UNSPECIFIED = 0, INVITE_ONLY = 1, OPEN = 2}
RoleIdList{role_ids: repeated u64 = 1}
OpenJoin{}
Space gains: join_policy: JoinPolicy = 13, open_join_role_ids: repeated u64 = 14
SpacePublicInfo gains: join_policy: JoinPolicy = 7
UpdateSpace gains: join_policy: optional JoinPolicy = 11, open_join_role_ids: optional RoleIdList = 12
Redeem.code gains: open_join: OpenJoin = 3
AuditAction gains: JOIN_POLICY_CHANGED = 15, OPEN_JOIN_ROLES_CHANGED = 16
```
- **`JoinPolicy`:** the server stores and sends `INVITE_ONLY` or `OPEN`, never `UNSPECIFIED`; a client treats `UNSPECIFIED` or a value it does not know as `INVITE_ONLY`. `update_space` with `join_policy = UNSPECIFIED` (or a value the server does not know) is `INVALID`.
- **`Space` fields:** both are in the snapshot form and the full form (§ 6.8), so they travel in the snapshot, `get_space` and `space_updated` (event 3, every member). There is no new event kind. `open_join_role_ids` is the stored list in ascending order, never `@everyone`; it shows what was set, and a join may skip some of it (below).
- **`SpacePublicInfo.join_policy`:** sent in `Hello` to every connection (§ 6.2), so a client that has only the address learns before `Auth` whether it can join. It is the stored policy; while `claimed` is false only the claim code can be redeemed, whatever the policy. A non-member learns of a later change only by reconnecting; a stale `open_join` just gets `FORBIDDEN`.
- **`UpdateSpace.open_join_role_ids`** is wrapped in `RoleIdList` so a patch can tell "unchanged" (absent) from "none" (present and empty), as § 6.8's patch rule needs.
- **`Redeem.open_join`** is a third variant of the existing `code` oneof (adding a variant is add-only, § 6.7). `OpenJoin` is empty: a set-but-false `bool` would mean nothing. `Redeem`'s hand-written `Debug` (§ 6.8) covers it as it covers the other variants.

**Setting it** (`update_space`, § 6.8). Opening the space (`join_policy = OPEN`) or setting `open_join_role_ids` needs `MANAGE_SPACE` **and** `CREATE_INVITES`: an open space is an invite without expiry or use limit, so a member who may not invite may not open it. Closing it (`INVITE_ONLY`) needs `MANAGE_SPACE` only, so a moderator can shut it during a raid. The permissions are checked on the fields present in the patch, before it is compared with the stored values. The fields are checked with the command's other fields, before anything is written; each role in `open_join_role_ids` must
- exist (`NOT_FOUND`), not be `@everyone` (`INVALID`) and not hold `ADMINISTRATOR` (`INVALID`: an open space never hands out administrator);
- pass `create_invite`'s check for `role_ids` exactly: below the actor's highest role, carrying only permissions the actor holds, and from M9 no more talk power than the actor's own (`FORBIDDEN`; the owner passes, § 8.1);
- and there are at most 50 of them, duplicates removed (`CONFLICT` over the limit, § 6.8 Limits). The limit is checked first, before any role is looked up; then the values (`NOT_FOUND`, `INVALID`), then the actor's check (`FORBIDDEN`).

The commit stores the policy and replaces the role list as a whole. When either actually changes, the actor becomes the **setter** (`space.open_join_set_by`, § 7.1: the member's account, or null for the operator API), and the commit publishes one `space_updated` and writes `JOIN_POLICY_CHANGED` when the policy changed (`value` = its `JoinPolicy` number) and `OPEN_JOIN_ROLES_CHANGED` when the list changed (no `value`); both name the actor (member or operator), so every change of setter is in the audit log. A patch that re-sends the current values changes nothing: not the setter, and no event or entry. Closing makes the closer the setter too; whoever reopens becomes the setter in turn, so a reopened space grants only the listed roles its reopener could give (step 4), never those of an earlier setter.

A role in the list that is **deleted** leaves it in the same commit (a foreign key `ON DELETE CASCADE`, § 7.1). That commit then also publishes `space_updated` after `role_deleted`, as deleting the default voice channel does (§ 6.11), so no member and no snapshot keeps a role id that is gone. It writes no extra audit entry. A role that later gains `ADMINISTRATOR` stays in the list and is skipped at join time.

**Joining** (`Redeem{open_join}`, a non-member session, § 6.2). In order:
1. **Rate limit first:** a token from the `rate_open_join_per_min` bucket of the address key (§ 5, in memory, § 9), taken on every attempt and never given back: an open join that passes always succeeds, so the refunding `rate_redeem_fail_per_min` bucket would never pace it, and an open join does not touch that bucket. An empty bucket is `RATE_LIMITED` with `retry_after_ms`; the connection stays open.
2. **Bans first:** an account in `bans` or queued in `erasures` gets `FORBIDDEN` (§ 6.2).
3. `FORBIDDEN` while the space has no owner (only the claim code works then, § 6.2), while the policy is not `OPEN`, or while the setter is a member account that is no longer a member or no longer holds `MANAGE_SPACE` and `CREATE_INVITES` (as an invite stops working with its creator, § 6.8). A connection or account that is already a member gets `CONFLICT`, as for an invite. These refusals of steps 2 and 3 are all the same `FORBIDDEN`, so a client cannot tell a ban from a closed space; `CONFLICT`, `RATE_LIMITED` and the device-list errors of the upgrade (§ 6.2) keep their own codes and connection behaviour.
4. **Upgrade in place** exactly as for an invite (§ 6.2, read states § 6.9), with the owner, the policy, the setter and, from M9, the member cap re-checked in the same transaction. The membership gets the listed roles that do not hold `ADMINISTRATOR` and, when the setter is a member account (`open_join_set_by` not null), that the setter could still give now (`create_invite`'s rule, as an invite re-checks its creator); the others are skipped.
- An open join writes no audit entry, as invite redemptions and claims write none (§ 6.12).
- **Member cap (M9):** with `max_members` above 0, a redemption (invite or open join) that would make the space hold more members than that, bots not counted, is `CONFLICT` with the fixed text "space is full", checked in the transaction that would create the membership, so concurrent joins cannot pass it; the connection stays open and nothing is used up (an invite's refusal still takes a token of the per-address failed-`Redeem` budget, as every refused invite does). The claim code is never refused for it. Lowering the cap removes no one. It is a config key, not a wire field (§ 5).

**Admin API** (§ 6.13, behind the same auth layer; errors map as § 6.13 maps a command's `ErrorCode`):

| Method | Path | Does | Notes |
|---|---|---|---|
| GET | `/api/v1/space/join-policy` | The policy and the open-join roles | `{"join_policy": "invite_only" \| "open", "open_join_role_ids": [..]}` |
| PATCH | `/api/v1/space/join-policy` | Sets either or both, with `update_space`'s checks except the hierarchy and permission cover (the operator acts for no account); stores no setter | Same body, both fields optional; a field present as `null` or an unknown field is `400 invalid`; `{}` changes nothing and answers `200`; `200` with the new state; audited as the operator |
| GET | `/api/v1/roles` | The roles, for the panel's picker | `{"roles": [{"id", "name", "position", "administrator": bool}]}`, highest first; names are user text, rendered as text |

The panel shows the setting on its status page as "Joining: Invite only / Open" with a role picker (from `GET /api/v1/roles`; `@everyone` and administrator roles are not offered). Choosing **Open** shows, before it is saved: bans are per identity (§ 6.12), so a banned person can come back at once with a new identity; only the per-address join limit slows that down.

**Ban evasion.** § 12.5 and § 9 count on invite-only joining as the defence against a banned person's new identities. An owner who opens the space gives that up knowingly (the warning above, the self-hosting guide, the API description). The brakes left are the `rate_open_join_per_min` bucket per address key and the connection limit (§ 9). Address-keyed bans stay #199's question (§ 12.5); an optional "open joiners start timed out" setting can follow, add-only.

**`yapsta-cli`** (§ 5): `space set yapsta://… --join-policy open|invite-only [--open-join-roles <id,id,…>|none]`, and `join --open yapsta://host[:port]`, which redeems `open_join` and prints the session as `whoami` does.

### 6.15 Bots and integrations (M8)

Bots use the native protocol exactly as people do (§ 3.6): a bot is a space member with an account, roles and voice, that authenticates with a key of its own instead of a device. Members also get slash commands that bots answer, and incoming webhooks that post into a text channel over HTTPS. Yapsta Bot is the first user (§ 10). `docs/BOTS.md` is the guide for bot authors.

**Objects**
```
BotCredential{bot_pub: bytes(32) = 1, signature: bytes(64) = 2}
Auth.credential gains: bot: BotCredential = 7
Member gains: bot: bool = 10
VoiceState gains: receiving_audio: bool = 9
SetVoiceState gains: receiving_audio: optional bool = 4
Message gains: webhook_id: optional u64 = 14, webhook_name: optional string = 15

Bot{account_id: u64 = 1, name: string = 2, created_at: u64 = 3, created_by: u64 = 4}
BotCreated{bot: Bot = 1, seed: string = 2}
BotList{bots: repeated Bot = 1}
enum CommandOptionKind{UNSPECIFIED = 0, STRING = 1, INTEGER = 2, BOOLEAN = 3, MEMBER = 4, CHANNEL = 5}
CommandOption{name: string = 1, description: string = 2, kind: CommandOptionKind = 3, required: bool = 4}
SlashCommand{name: string = 1, description: string = 2, options: repeated CommandOption = 3}
CommandList{bot_account_id: u64 = 1, commands: repeated SlashCommand = 2}
CommandOptionValue{name: string = 1, oneof value{text: string = 2, integer: sint64 = 3, boolean: bool = 4, account_id: u64 = 5, channel_id: u64 = 6}}
Interaction{invoker_id: u64 = 1, channel_id: u64 = 2, name: string = 3, options: repeated CommandOptionValue = 4}
CommandsUpdated{bot_account_id: u64 = 1}
Webhook{id: u64 = 1, channel_id: u64 = 2, name: string = 3, created_by: u64 = 4, created_at: u64 = 5}
WebhookCreated{webhook: Webhook = 1, token: string = 2}
WebhookList{webhooks: repeated Webhook = 1}

CreateBot{name: string = 1}
RotateBot{account_id: u64 = 1}
DeleteBot{account_id: u64 = 1}
RegisterCommands{commands: repeated SlashCommand = 1}
InvokeCommand{bot_account_id: u64 = 1, channel_id: u64 = 2, name: string = 3, options: repeated CommandOptionValue = 4}
CreateWebhook{channel_id: u64 = 1, name: string = 2}
DeleteWebhook{webhook_id: u64 = 1}
BotListRequest{}
CommandListRequest{bot_account_id: u64 = 1}
WebhookListRequest{}

Command gains: create_bot = 60, rotate_bot = 61, delete_bot = 62, register_commands = 63,
               invoke_command = 64, create_webhook = 65, delete_webhook = 66
Request gains: bot_list = 16, command_list = 17, webhook_list = 18
CommandResult gains: bot_created: BotCreated = 10, webhook_created: WebhookCreated = 11
Response gains: bot_list: BotList = 11, command_list: CommandList = 12, webhook_list: WebhookList = 13
Event gains: commands_updated: CommandsUpdated = 29
Ephemeral gains: interaction: Interaction = 8
AuditAction gains: BOT_CREATE = 17, BOT_ROTATE = 18, BOT_DELETE = 19, WEBHOOK_CREATE = 20, WEBHOOK_DELETE = 21
```
- **Hand-written `Debug`** (§ 7.6): `BotCreated` shows no seed, `WebhookCreated` no token, `BotCredential` the key but not the signature; `Interaction`, `InvokeCommand` and `CommandOptionValue` show ids, the command name and the count of options, never option values (they are user text, § 6.9).
- **No snapshot field.** Commands are fetched per bot (`command_list`, below), never carried in the snapshot: at the limits below one bot's set is up to about 75 KB, and the snapshot frame is at most 1 MiB (§ 6.3).
- **Reply reservations** (§ 6.1): `bot_list` and `webhook_list` 64 KiB, `command_list` 128 KiB.

**Commands and requests**

| # | Kind | Needs | Reply |
|---|---|---|---|
| 60 | `create_bot` | `MANAGE_SPACE` | `CommandResult.bot_created` |
| 61 | `rotate_bot` | the owner only (operator: the admin API) | `CommandResult.bot_created` (the new seed) |
| 62 | `delete_bot` | `MANAGE_SPACE`; the bot ranked below the actor (§ 8.1) | `Ack` |
| 63 | `register_commands` | a bot session; 5 per minute per bot (fixed, bucket size = the rate) | `Ack` |
| 64 | `invoke_command` | `USE_COMMANDS` on the channel; `rate_message_*` | `Ack` |
| 65 | `create_webhook` | `MANAGE_WEBHOOKS` and `SEND_MESSAGES` on the channel | `CommandResult.webhook_created` |
| 66 | `delete_webhook` | `MANAGE_WEBHOOKS` on its channel | `Ack` |

| # | Request | Needs | Response |
|---|---|---|---|
| 16 | `bot_list` | `MANAGE_SPACE` | `bot_list`: every bot, newest first (`created_at`, then `account_id`, descending) |
| 17 | `command_list` | members | `command_list`: the bot's set in registration order |
| 18 | `webhook_list` | `MANAGE_WEBHOOKS` on at least one channel | `webhook_list`: the webhooks of the channels where the member holds it, by `id` ascending |

Check order is § 6.8's: existence and visibility (`NOT_FOUND`), permission and hierarchy (`FORBIDDEN`), values (`INVALID`), limits (`CONFLICT`), then the rate (`RATE_LIMITED`). An `account_id` or `bot_account_id` that is not a bot is `NOT_FOUND`, as a missing one is.

**Bot accounts**
- **Creating** (`create_bot`): `name` follows § 6.8's display-name rules (1–32 bytes, no control or format characters). At most 50 bots per space (`CONFLICT`). In one transaction the server mints an account (an `accounts` row whose `account_pub` is 32 bytes from the OS RNG that no key holder has), the `bots` row with `bot_pub`, and the membership (`display_name` = `name`, no roles besides `@everyone`), writes `BOT_CREATE` (actor, target = the bot) and publishes `member_joined`. `Member.bot` is true exactly when the account has a `bots` row. The reply carries the **seed** once: 32 bytes from the OS RNG as 52 lowercase RFC 4648 base32 characters without padding. Seed `00 01 … 1f` is `aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq`. Readers of a seed (bot libraries, `yapsta-cli`) ignore surrounding whitespace and accept either case. The server holds the seed only to derive `bot_pub` and send the reply (in zeroizing buffers), then forgets it; nothing can show it again.
- **The bot key:** `Ed25519(HKDF-SHA256(seed, salt="yapsta/bot/v1", info=server_id))`, derived exactly as the account key (§ 6.2): extract with salt = the 13 ASCII bytes `yapsta/bot/v1`, expand with `info` = `server_id` to 32 bytes, used as the RFC 8032 seed form. Test vector: seed `00 01 … 1f` and `server_id` `a5jy5opmsxgrcsn22buvxzm5qi` give the secret key `5ec4a3369d1b8aca6df6ca4a1680171f21730509450c8d03646ad560146430f1` and `bot_pub` `b0efb9627014cc8717bb62cb7f22fb06deb90dcf26b52860ab643b8d6ee71326`. `yapsta-proto`'s `identity` module implements it.
- **Who a bot is:** an ordinary member with `Member.bot = true` in both forms: roles, overwrites, the hierarchy, nicknames, its own profile (a bot session may `update_profile`; `Bot.name` is its current display name), voice and messages work as for anyone. Managers give it roles with `add_member_role`; "scoped permissions" are its roles and overwrites. Whoever holds the seed acts as the bot, so giving a bot a role trusts its seed's holders with it. A bot can never be the owner (`transfer_ownership` to a bot is `INVALID`), never be on either side of `transfer_member` (`INVALID`), and never redeem (its sessions are members already: `CONFLICT`).
- **Rotating** (`rotate_bot`): a new seed and `bot_pub` in one transaction, `BOT_ROTATE` written; the bot's session is closed with `UNAUTHENTICATED` and its resume tokens are dropped in the same apply step. The account, membership, roles and commands stay. Only the owner (or the operator) may rotate: the new seed carries every permission the bot holds, which a manager below the owner may lack (§ 8.1: a member never grants a permission they do not hold).
- **Deleting** (`delete_bot`), and **kicking or banning a bot** (§ 6.12, with their usual checks): in one transaction the `bots` row (with its commands), the webhooks the bot created and the membership go (a ban also writes the `bans` row), `member_removed` is published (`reason` `KICKED`, or `BANNED` for a ban), its session is closed with `MEMBER_REMOVED` and its resume tokens dropped. The audit entry is `BOT_DELETE`, `KICK` or `BAN`. The `accounts` row stays, as for any former member (§ 6.2), so `account_id`s are never reused; the deleted key no longer authenticates. A timeout works as for any member. An erasure of a bot's account (§ 6.13) deletes the bot first, without a `BOT_DELETE` entry (the `ERASE` entry records it).

**Bot authentication** (`Auth{credential: bot}`, § 6.2)
- The bot signs the **bot `Auth` transcript** (§ 6.2 Signed byte strings): `yapsta/bot-auth/v1` `0x00` ‖ `server_id` (26) ‖ `challenge` (32) ‖ `exporter` (32) ‖ `bot_pub` (32), with the same exporter as devices. So a bot connection is bound to its TLS session and fresh challenge exactly as a device's is, and every connection signs. `Auth` does no argon2 for bots either.
- **Checks, in order:** `Auth.version` ≥ 8; `bot_pub` 32 bytes and `signature` 64; `verify_strict` of the signature (weak keys rejected, § 6.2); the `bots` row for `bot_pub` (read pool; a rotated or deleted key has none). Any failure is the same `UNAUTHENTICATED` close, and every bot `Auth` takes a token from the failed-`Auth` bucket (§ 9) before any work, given back on success, as for devices.
- **Registration re-checks the key:** the hub keeps each bot's current `bot_pub` in memory (loaded at start, changed in the apply step of `create_bot`, `rotate_bot`, deletion, kick, ban and erasure; from M9 also of every re-key, § 6.12, including the transitive ones and the first-start cleanup). Registering a bot session (a resume included) happens in the hub's apply order and compares the `Auth`'s `bot_pub` with the current one; a key rotated or deleted after the read-pool lookup is closed with `UNAUTHENTICATED` and gets no `Welcome`. So a rotation always wins over a login that was in flight when it committed.
- **The device path refuses bots:** a `DeviceCredential` whose `account_pub` belongs to an account with a `bots` row is `UNAUTHENTICATED`, whatever it signs.
- **`Welcome`** is a member's: `account_id`, `membership`, `resume_token` and the snapshot; no `device_list`. Resume works as for devices, with tokens keyed on the account and `bot_pub`, so a rotated key's tokens are gone.
- **One session per bot:** a second bot `Auth` replaces the first, which is closed with `SESSION_REPLACED` (§ 6.3), as a device's second session is. A bot that needs voice in several channels uses several bots.

**Voice and the receiving-audio indicator**
- A bot joins voice under § 6.10 unchanged: `CONNECT`, the password, the limits, QUIC datagrams only (`join_voice` over TCP is `CONFLICT`). It never takes the lobby on connect (§ 6.11): connecting never puts a bot in voice, only its own `join_voice` does. It hears every speaker separately: forwarded copies carry the sender's `session_ref` (§ 6.4), so it decodes per person, and the server never mixes, decodes or records voice. It speaks under `SPEAK`, talk power, server mute and timeouts, through the per-session datagram bucket.
- **`VoiceState.receiving_audio`** tells everyone in the channel that a session takes in the channel's audio for more than listening (a bot, or a client that records). For a **bot** the server sets it: true while the bot is in voice and not deafened (self or server), and its own `SetVoiceState.receiving_audio` is ignored. For **other sessions** it is self-declared with `SetVoiceState.receiving_audio` (the same 10 per 10 s bucket, § 6.10) and reported as declared while the session is not deafened, false while it is. It is cleared when the session leaves voice; a move (`move_member`) keeps it, while the session's own `join_voice` to another channel starts without it, as with the self flags (§ 6.10).
- **Guarantee:** only the bot value is enforced. The server cannot tell whether a client records (it never sees decoded audio), so a client that records without declaring it shows nothing; every non-deafened session in a channel receives its audio (§ 6.10). Clients say so where they show the marker.
- **Delivery:** the value travels in `VoiceState` (the snapshot's `voice_states`, `voice_state_updated`), computed when routes are rebuilt (§ 6.4), never per datagram. A `voice_state_updated` is published only when some field of the state actually changed. Minor-7 sessions receive the field and ignore it; a minor-7 session that sends `SetVoiceState.receiving_audio` gets `INVALID`.

**Slash commands**
- **Registering** (`register_commands`, bot sessions only, else `FORBIDDEN`): the set replaces the bot's whole set (an empty list removes them all), stored with the bot (§ 7.1). Limits: at most 50 commands, each with at most 10 options; command and option `name` 1–32 bytes of `a`–`z`, `0`–`9`, `_` and `-`, unique within the set or command; `description` 1–100 bytes, display-name rules; option `kind` 1–5 (`UNSPECIFIED` or a kind this server does not know is `INVALID`); required options before optional ones. Anything else is `INVALID`. The commit publishes `commands_updated{bot_account_id}` to every member; it carries no commands, so the event and its ring entry stay small. Deleting the bot removes its commands and publishes nothing more (`member_removed` says it is gone).
- **Listing** (`command_list{bot_account_id}`): one bot's commands, through the reader pool. Clients fetch a bot's set when they need it and again after `commands_updated`.
- **Invoking** (`invoke_command`), in order: the channel exists and is visible, the bot exists, and the command is in its set (`NOT_FOUND`); `USE_COMMANDS` on the channel, the invoker not under a timeout (it makes a bot post, so it is refused as `send_message` is, § 6.12), and the bot can see the channel (`FORBIDDEN`); the options match the command: no unknown or repeated name, every required one present, each value set and of the declared kind, `text` 1–1,000 bytes, a `MEMBER` value a member and a `CHANNEL` value a channel the invoker can see (`INVALID`); a token from the invoker's `rate_message_*` bucket (`RATE_LIMITED`); last, the bot has a live session (`UNAVAILABLE`, which does not close the connection, and the token is given back). The hub delivers in its apply order and checks again there: a bot whose outbound queue is full is also `UNAVAILABLE` (the bot is not disconnected, unlike § 6.1's `SLOW_CONSUMER` rule for other frames), and a bot that lost sight of the channel between the checks and delivery is `FORBIDDEN`; in both cases nothing is queued and the token is given back. Then the bot's session gets one `interaction` ephemeral and the invoker gets `Ack`. Nothing is written or kept: invocations and option values are never stored or logged, and the server forgets an interaction once it is queued.
- **Answering:** a bot answers with `send_message` in the interaction's channel, under its usual checks. Yapsta has no autocomplete (P2, § 3.6).

**Incoming webhooks**
- **Managing:** `create_webhook` on a **text** channel (`INVALID` on any other kind: a voice channel's chat has its own readers, § 6.11), `name` by the display-name rules; at most 10 webhooks per channel and 50 per space (`CONFLICT`). The reply carries the **token** once, in the admin token's form (§ 6.13): `<id>.<secret>`, an 8-byte token id as 16 hex characters and a 16-byte secret as 26 base32 characters. The token id is not the webhook's id and never appears on the wire. `webhooks` (§ 7.1) stores the token id and an argon2id PHC hash of the secret with the claim code's parameters. `delete_webhook` revokes it at once. Deleting a channel deletes its webhooks (no audit entry). `create_webhook` and `delete_webhook` write `WEBHOOK_CREATE` and `WEBHOOK_DELETE` (`value` = the webhook's id).
- **A webhook lives with its creator,** as an invite does (§ 6.8): it posts only while its creator is a member who sees its channel (`VIEW_CHANNEL`), holds `MANAGE_WEBHOOKS` and `SEND_MESSAGES` there and is not under a timeout (§ 6.12), so a webhook never posts what its creator could not. Otherwise a post is `403` and nothing is written; the webhook works again once the creator qualifies again (a lost permission or a timeout is temporary). **Any removal of the creator's membership** (a kick, a ban, `transfer_member` from it, a bot's deletion, the removal that starts an erasure) **deletes its webhooks in the same transaction**, and an erasure deletes them in its queue transaction even when the account is no longer a member; so a removed creator's tokens are `401` from the next request. From M9 the bots a removed member created are re-keyed, not deleted, and the webhooks those bots created are deleted (§ 6.12): no credential the creator held still works, and the owner (or the operator) restores the bot with `rotate_bot`.
- **The token-id set:** the server keeps every webhook's token id in memory (at most 50). The set is loaded at startup and after a restore, and changes in the same apply step as every change of a `webhooks` row (create, delete over the wire or the admin API, a channel's delete, any removal or erasure of the creator, above), which also drops the token's cache entry: it follows each commit's deltas as the write path hands them to the hub, before the command is answered. So a created webhook posts, and a removed webhook's token fails at step 1, from the next request.
- **Posting:** `POST /webhooks` with the header `Authorization: Bearer <id>.<secret>`, or `POST /webhooks/<id>.<secret>` for senders that can only be given a URL (both at once is `401`; one path segment after `/webhooks/` is always read as a token, `401` when malformed; a deeper path is `404`; another method `405`), on the HTTPS listener (§ 6.1, port 7121). `crates/net` serves both beside `/files` and `/uploads`, so they work whether or not the admin API is on. The body is JSON with a `content` string; other fields (such as a Discord sender's `username` or `embeds`) are ignored. Per request, in order:
  1. **Token id:** a missing or malformed token, or an id not in the token-id set, is `401` with no database read, no hash and no bucket, so guessing costs the guesser and nothing else. A post that arrives at startup before the set has loaded waits for it, at most 10 s, then is `503`.
  2. **Per token id:** a token from that webhook's failure bucket (5 per minute, fixed, bucket size = the rate), taken before the secret is checked and given back once it verifies; empty: `429` with `Retry-After`. It is keyed by the token id, not the address, so a reverse proxy in front of 7121 (every request then comes from its address) never lets one sender block another's webhook.
  3. **Verify from the cache** (token id → SHA-256 of the secret, in memory, constant-time compare), as admin tokens (§ 6.13); else **argon2id** in the redeem `HashPool` behind an admission shared with the admin API (one running or waiting for both together; past it `503` with `Retry-After` and the bucket token given back), so at least one of the pool's two places is always free for `Redeem` and channel passwords. A wrong secret is `401`, and every `401` answers the same body. Concurrent cache misses for one token id wait on the first verification (single-flight), so only it takes the admission place; a burst to one webhook right after a restart costs one hash, not `503`s. The shared verification only fills the cache: each waiter then compares its **own** secret's SHA-256 with the cache entry (constant time), and a waiter whose secret does not match, or whose leader's verification failed, goes through this step on its own (its own admission place and argon2, or `401`). No request is ever accepted on another request's secret.
  4. **The creator** still qualifies (above): else `403`. Read on the reader pool with the webhook's row: a row gone or no longer the one with this token id is `401`, as at step 1.
  5. **Pace:** a token from the webhook's `rate_webhook_per_min` bucket (default 30, burst `rate_webhook_burst` 5; in memory, keyed by webhook); empty: `429` with `Retry-After`. The channel's slowmode applies per webhook (`429`).
  6. **Body:** at most 16 KiB, checked on `Content-Length` and while the body streams (`413`); not JSON, no `content` string, or a `content` outside § 6.9's rules (1–4,000 bytes): `400`.
  7. **Post:** a writer job (`BEGIN IMMEDIATE`) re-checks, from the rows of its own transaction, that the `webhooks` row still exists with the same id, channel and token id that authenticated the request (a deleted and re-created webhook never inherits a post in flight) and that the creator still qualifies (as § 6.9 re-checks a command's permission, since permissions captured before the job may be stale); else `403` and nothing is written. Then it stores the message with no author account, `webhook_id` and `webhook_name` (the name at posting time); mentions of members are parsed as in § 6.9; `@everyone`, `@here`, role and channel mentions are not (a webhook holds no `MENTION_*` and sees no channel tree). `204` after the commit, then `message_created` reaches the channel's readers. A failed write is `503` and posts nothing.
- **The verifier** (token parsing, the SHA-256 cache, the shared admission, the PHC check) is one component in `crates/net` that the admin API (`crates/admin`) and webhooks both use; it moves there from `crates/admin` with the webhook ticket.
- **Webhook messages:** on the wire `author_id` 0 means the message has no member author: with `webhook_id` set it is a webhook's, without it a deleted member's (§ 7.3). A minor-7 client shows webhook messages as from a deleted member. They can be edited by nobody and deleted with `MANAGE_MESSAGES`; `from:` search never matches them; erasure never touches them. Deleting a webhook keeps its messages.
- **TLS:** senders verify the listener's certificate like any HTTPS client; until ACME (§ 5) it is self-signed, so a sender pins it or the operator puts a reverse proxy with a CA certificate in front.
- **Privacy:** metric label `/webhooks` for both forms (§ 7.6). Webhook bodies, tokens, the `Authorization` header and the path's token never appear in logs, `Error` bodies or metrics. A reverse proxy's own access log would record the URL form's token; operators who log paths use the header form. Outgoing webhooks are not part of Yapsta (no outbound calls).

**Admin API** (§ 6.13, behind the same auth layer):

| Method | Path | Does | Notes |
|---|---|---|---|
| GET | `/api/v1/bots` | The bots | `{"bots": [{"account_id", "name", "created_at", "created_by", "online": bool}]}`, in `bot_list`'s order |
| POST | `/api/v1/bots/{id}/rotate` | `rotate_bot`, as the operator | `200` `{"seed": "…"}`, shown once; audited as the operator; an unknown or non-bot id is `404` |
| DELETE | `/api/v1/bots/{id}` | `delete_bot`, as the operator | `204`; `404` as for rotate |
| GET | `/api/v1/webhooks` | The webhooks | `{"webhooks": [{"id", "channel_id", "name", "created_by", "created_at"}]}`, by `id` ascending |
| DELETE | `/api/v1/webhooks/{id}` | `delete_webhook`, as the operator | `204`; an unknown id is `404` |

The panel lists bots and webhooks with Rotate and Delete; a rotated seed is shown once in a dialog and kept nowhere. Bots and webhooks are created by members over the wire.

**`yapsta-cli`** (§ 5): `bot create <name> --seed-file <path>` (writes the seed to a new 0600 file, prints the bot), `bot list|rotate|delete`, `connect --bot-seed-file <path>` (authenticates as the bot; `voice` and `chat` then work as for a member), `command register <file>` (a line-based set: `command <name> <description>` lines, each followed by its `option <name> <kind> required|optional <description>` lines), `command list <bot>|invoke <bot> <channel> <name> [opt=value …]`, `command serve` (as a bot, answers each interaction with a fixed message), `webhook create <channel> <name> --token-file <path>` (a new 0600 file), `webhook list|delete <id>`, and `webhook post yapsta://host[:port] --token-file <path> <text> [--https-port <port>]` (no session: the header form to the host's HTTPS listener, default 7121, pinned to the key the home pinned for that server).

### 6.16 Hardening (M9)

M9 acts on the security and efficiency audit of 2026-11-14 (`docs/security-audit-2026-11-14.html`; ids such as H1 or M5 below are its findings, not milestones). Most of it adds limits to what § 6.1–§ 6.15 already describe, in the sections it changes; this section collects them and states the one new command. Every limit here is fixed unless § 5 lists a key for it. Each refusal is an existing `ErrorCode`, counted in `/metrics` under a fixed reason label, never with an id or an address (§ 7.6).

**Objects** (minor 9, § 6.7)
```
DeleteThread{thread_id: u64 = 1}
Command.kind gains: delete_thread: DeleteThread = 67
ThreadDeleted{channel_id: u64 = 1, thread_id: u64 = 2}
Event.kind gains: thread_deleted: ThreadDeleted = 30
AuditAction gains: ROLE_CREATE = 22, ROLE_UPDATE = 23, ROLE_MOVE = 24, ROLE_DELETE = 25,
                   MEMBER_ROLE_ADD = 26, MEMBER_ROLE_REMOVE = 27, OVERWRITE_SET = 28, OVERWRITE_DELETE = 29,
                   CHANNEL_CREATE = 30, CHANNEL_UPDATE = 31, CHANNEL_MOVE = 32, CHANNEL_DELETE = 33,
                   INVITE_CREATE = 34, INVITE_REVOKE = 35, THREAD_DELETE = 36, TEMPLATE_APPLY = 37
```
No new `Request`, `Response`, `CommandResult`, ephemeral, `ErrorCode`, capability or close code; the member cap is a config key, not a wire field.

**Unauthenticated and non-member work (H1, H2, L1, L2)**
- **Connections before `Welcome`:** at most 256 at once, all addresses together, on QUIC and TCP together. An attempt beyond it is refused as one over the connection-attempt limit (§ 9: QUIC `CONNECTION_REFUSED`, TCP dropped before TLS), after the stateless Retry, so spoofed packets cannot fill it. A connection holding a place has 20 s from the end of its transport handshake to authenticate: a `Hello` not written by then closes it with `SLOW_CONSUMER`, and the wait for its `Auth` ends there as well (`UNAUTHENTICATED`, "no Auth in time"), so a client that does not read or does not answer holds a place for that long at most. The place is free once the server has accepted the `Auth` and is about to write `Welcome` (which then has the whole send timeout, as a large snapshot may need), or when the connection ends.
- **Small frames first:** until its `Welcome`, and for the whole of a non-member session, a client's frames on the control stream are at most 32 KiB (the largest legal `Auth` is under 18 KiB, § 6.1); a larger length prefix is `TOO_LARGE` and closes the connection before any byte of the body is read.
- **Body tag before body:** the server walks the `Envelope`'s field tags before decoding any body; a frame carrying any body only a server ever sends (protobuf allows several oneof fields in one frame, the last one winning) (`error` 3, `hello` 4, `welcome` 6, `event` 7, `ephemeral` 8, `ack` 10, `resync` 13, `command_result` 15, `response` 17) is `INVALID` and closes the connection, so a frame packed with empty repeated messages is never expanded. A body number added later says which side sends it.
- **Partial frames:** before `Welcome` and for non-members, once a frame's first length byte has arrived on the control stream, the whole frame must arrive within 10 s (the `Auth` deadline's length); otherwise `INVALID`, closing. Members' frames have no such clock (§ 6.1).
- **Non-member sessions:** a session whose `Welcome` carried no membership ends with `UNAUTHENTICATED` 120 s after that `Welcome` unless a `Redeem` (§ 6.2, § 6.14) made it a member. At most 256 are held in all and 4 per address key; an `Auth` that would pass either cap is closed with `RATE_LIMITED` and a `retry_after_ms` instead of a `Welcome`. A non-member's body other than `Redeem`, `Ping` and `fetch_space_icon`, and any frame of it that does not decode, closes the connection (`FORBIDDEN` or `INVALID`).
- **The /48 tier:** the in-memory limiter keeps, beside each IPv6 /64 bucket for connection attempts, failed `Auth`, failed `Redeem` and open joins, a bucket for its /48 at 8 times the rate and size; an attempt takes from both (§ 5). IPv4 addresses have one tier. The tier shares the limiter's bound on keys, and no key is logged or used as a metric label.
- **Hash places:** of the redeem pool's 2 argon2 places (§ 6.2), claim-code hashes use at most one at a time and wait in a queue of their own (64 waiting); channel passwords and admin and webhook token verifications share the pool's other queue (64 waiting) and may use both places, so a flood of claim attempts never fills their queue. A `Redeem` turned away because the claim queue is full keeps its rate-limit token, so overflow attempts are no longer free. Total argon2 concurrency stays 2.

**Commands that lacked a limit (M1, M11, L14)**
- `update_profile`, `set_avatar` and `set_nickname` take a token from `rate_profile_per_min` (bucket `rate_profile_burst`) of the actor's account before their checks commit anything; `create_thread` and `update_thread` take one from `rate_message_*`. Past it: `RATE_LIMITED` with `retry_after_ms`, no commit, no event.
- From M12 `delete_message`, `remove_reaction`, `delete_dm_message` and `remove_dm_reaction` take a `rate_message_*` token first too, whatever the outcome (#431; why `mark_dm_read` and invalid SDP answers stay unmetered: § 9).
- A member under a timeout (§ 6.12) gets `FORBIDDEN` for `update_thread`, `update_profile`, `set_avatar` and `set_nickname` of their own, as for sending.
- `update_thread` with `archived = false` needs `MANAGE_THREADS`; the creator may still rename and archive.
- A `member_updated` about another member that changes no roles (a profile, nickname or avatar change) is not a visibility change, so it no longer turns a resume into a snapshot (§ 6.3).
- **Reads:** a session runs at most 2 requests against the read pool at once; more wait in the session, never refused, so no new error reaches a client. From M12 an account runs at most 2 across all its sessions too, and a request waiting for reply budget lends its account place meanwhile; a search's run keeps its place until its reader is let go, even past a dropped request (#431, § 9). An upload gives its place back before its image work and disk writes. Commands, which run one at a time per session, take none. `get_messages` loads only the chains of the channels of the messages asked for, in a fixed number of statements.
- **Queued commands** count against a per-connection command allowance of 4 MiB, separate from the reply budget, until they have run; when it is full the server stops reading the control stream instead of refusing (§ 6.1).

**`delete_thread`** (command 67, M1 follow-up)

| # | Kind | Fields | Allowed for | Reply |
|---|---|---|---|---|
| 67 | `delete_thread` | `thread_id` | `MANAGE_THREADS` on the thread's channel | `Ack` |

- **Check order** is § 6.8's: the thread exists and its channel is visible with `READ_HISTORY` (`NOT_FOUND`, the same answer for a missing and a hidden thread); `MANAGE_THREADS` (`FORBIDDEN`). Under a timeout: `FORBIDDEN`. Threads switched off (§ 6.11) does not stop a delete.
- **Effect:** one writer job marks the thread deleted and publishes `thread_deleted{channel_id, thread_id}` (event 30) to the sessions with `VIEW_CHANNEL` on the channel, as `thread_updated` goes (§ 6.9), and writes a `THREAD_DELETE` audit entry. From that commit the thread's messages are out of history, search, `get_messages` and pins; their rows, search entries, mentions, reactions, pins and attachment rows go as a deleted message's do (§ 7.3), at most 500 per writer job, housekeeping finishing a large thread, and they leave no tombstone. The root message stays as an ordinary message of the channel; the thread row stays, marked deleted, until its last message is gone, and until then `create_thread` on that root is `CONFLICT`, so a new thread never inherits the old one's messages. Then the row goes. A thread marked deleted is a missing thread to everything else: every command and request naming it (`send_message`, `update_thread`, `delete_thread`, `history`, `mark_read` on its messages, …) is `NOT_FOUND`, and it is left out of `list_threads`, the snapshot and `resync`, so nothing can be added to it while it empties and a minor-8 client's stale view gets ordinary errors. Each removed message is redacted in the resume ring, as an erasure redacts (§ 6.13). `thread_deleted` is not a visibility change.
- A minor-8 session is sent no `thread_deleted` (§ 6.7).

**Removal cleans up after the member (M2, M9)**
- Every removal of a membership (kick, ban, transfer of `from`, erasure, § 6.12) also clears, in its transaction, the `allow` bits of the member overwrites naming the account, deleting those left with no `deny` (published as `overwrite_set` or `overwrite_deleted` after the commit's other events, and resynced where it changes what a session sees, § 6.3); denies stay, so a kick never lifts a channel mute. An account that rejoins gets back no channel grant.
- Every such removal except `transfer_member` also re-keys the bots the account created: `bot_pub` becomes the public key of a freshly generated key pair (OS RNG) whose secret is dropped at once, the bot's sessions close with `UNAUTHENTICATED` as after `rotate_bot`, the webhooks the bot created are deleted (their tokens were shown to whoever ran it), and the bot keeps its roles and commands until the owner, or the operator through the admin API, runs `rotate_bot`. The same applies to every bot a re-keyed bot created, transitively, and the invites the re-keyed bots created are revoked, so nothing the removed creator could reach through their bots (a seed, a webhook token, an invite code, a bot made by their bot) still works, and no one loses a bot the remover could not have deleted. One `BOT_ROTATE` entry per bot is written with the removal's actor; the deleted webhooks write no `WEBHOOK_DELETE` entry (as a channel delete writes none) and leave the in-memory webhook token-id set in the same apply step (§ 6.15).
- **Before M9:** the first start of an M9 server applies the same two steps once to every account that is not a member (for an account that a kept `TRANSFER_MEMBER` audit entry names as `from`, the bots it created before that entry's second first get that entry's `to` as `created_by`, as the transfer did (a bot made later, or in that same second, stays its own), and they are re-keyed only if `to` is not a member either; one whose entry retention has pruned is re-keyed, and the owner restores its bots with `rotate_bot`), so removals before M9 leave no grant and no live seed behind. It writes one `BOT_ROTATE` entry per re-keyed bot as the operator, and nothing else, and marks itself done in the same transaction (a row the M9 migration creates as pending), so a later start skips it and a restored pre-M9 backup, migrated by `restore`, gets it at its next start.

**Files (M5, L10, L11)**
- `quota_space_bytes` defaults to 10 GiB; `min_free_disk_bytes` (1 GiB) refuses an upload or upload slot with `CONFLICT` while the data directory's filesystem has less free space, checked once at its start off the tokio workers.
- `upload_attachment` and `upload_url` need `ATTACH_FILES` on at least one channel the member can see (`FORBIDDEN`); `send_message` still checks it on the message's channel.
- The wait for the image-decode slot (§ 6.5) is bounded at 5 s; past it the attachment is stored without a thumbnail, as for an image the helper refuses, and an avatar or emoji upload is `UNAVAILABLE` ("the image worker is busy"), counted as `decode_wait`. That upload has already taken its upload token and slot, so a retry may first meet `RATE_LIMITED` with `retry_after_ms`.
- The HTTPS listener's 1,024 connections (16 per address key) keep room for completed handshakes: connections still in their TLS handshake may hold at most a quarter of them (256); when that share, or all 1,024 places, are full, a new connection closes the oldest handshaking connection of the address key holding the most of them (the oldest of the tied keys' on a tie), as the ICE-TCP listener does (§ 9), counted as `https_handshake_evicted`, so a flood of half-open handshakes cannot block files and the panel. A connection whose handshake has completed is never closed for a newcomer; with every place held by completed connections, a newcomer is dropped before TLS as before.

**Voice and media (M3, M4, M8, L12, L13)**
- Voice: 64,000 bytes a second per sending session beside the 120 datagrams (§ 6.10).
- SFU: a connected peer's address is pinned and an address another connected peer nominated is never taken; per-track bitrate caps end a track that stays over them for 5 s; `answer_media` after an accepted answer is `CONFLICT` before parsing (§ 6.6).
- **Supervision:** the media thread drives each peer under a panic guard, around every call into its `Rtc` while it routes, times and forwards media, and around each `publish_media`, `subscribe_media` and `answer_media` it handles. A panic ends that peer's track or subscription with `FAILED` (in a request, the request's own id, answered as an ended id), its `Rtc` is dropped unused, and the thread carries on with the others. If the media loop itself ends, every track and subscription ends with `FAILED`, requests already queued are dropped and new media commands are `UNAVAILABLE`, and the loop starts again on the same thread at most once a minute (60 s after its last start), keeping its UDP socket and ICE-TCP listener bound meanwhile. If the hub task ends while the server runs (a panic, or a failed load of the space), the server shuts down as for a signal and exits with status 1, so the container's restart policy brings it back and `/healthz` never reports a server that serves nothing. Containment needs unwinding: no build profile may set `panic = "abort"` (a test checks the workspace's profiles). The media thread counts the peers its guards ended and its restarts, content-free.

**Admin, backups and hosting (M6, M7, M10, L16)**
- A valid cached admin token is authenticated before the failure bucket (§ 6.13), and from M12 a live token whose address's bucket is empty takes from a bucket of its own (§ 6.13 step 1a, #433); concurrent first uses of one token id run one hash, and each request is still judged by its own secret.
- Restore revokes every admin token, and from M12 every bot key, webhook and live invite (#434); live backups keep the newest `backup_keep` (§ 7.5).
- The 7121 listener sends HSTS, and the certificate's fingerprint is logged at start and printed by `yapsta-server tls-fingerprint` (§ 6.13). The self-hosting guide (`docs/SELF-HOSTING.md`) says how to run behind a CA-certified reverse proxy (UDP 7120 and 7122 bypass it; `public_https_base` is needed), when to firewall 7121 or set `admin_api = off`, how to upgrade (back up first; migrations are one-way), and that the owner claim code stays in container logs until redeemed.

**Management (L3, L5, L6, L18, L4)**
- Talk power given is at most the actor's own (§ 6.8). `revoke_invite` answers one `NOT_FOUND` for a missing invite and one the actor may not revoke.
- Names refuse line separators and default-ignorable code points outside emoji (variation selectors, U+200D between pictographs and flag tag sequences stay); thread names and poke text follow the name rules (§ 6.8, § 6.9).
- Role, member-role, overwrite, channel and invite management, `delete_thread` and `apply_template` write audit entries with ids only (§ 6.12); `apply_template` writes one, not one per created object. An entry is written only when the command changes something (a patch or move that changes nothing, an overwrite set to the bits it has, a role a member already holds, an invite already revoked: none), and `set_channel_password` counts as `CHANNEL_UPDATE`, except a clear of a channel with no password. A member's temporary voice channel (`CREATE_TEMP_CHANNEL`, § 6.10) writes none, and neither does its removal when empty: it is not management, and its entries would record who used voice when. A manager's edit, overwrite or delete of a temporary channel is management and is audited as for any channel.
- `max_members` caps the members of the space, bots not counted (§ 6.14).

### 6.17 DMs and the personal stream (M10)

Direct messages between members of the instance's space: 1:1 conversations and group DMs of up to 10, with blocking, read states, typing and attachments. They are personal, not space objects: they travel only on the personal stream (§ 6.3, "Personal stream, M10") and in their own requests, never as an `Event`, so space visibility, `channel_of`, search, the space ring and every minor-9 session are untouched. DMs are encrypted in transport (TLS, § 9) and readable by the server; end-to-end encryption for DMs comes with MLS after 1.0 (§ 7.7), and client text must not suggest otherwise. Conventions as § 6.8 and § 6.9; everything here needs minor 10 (§ 6.7).

**Objects**
```
enum DmKind{DM_KIND_UNSPECIFIED = 0, ONE_TO_ONE = 1, GROUP = 2}
Dm{id: u64 = 1, kind: DmKind = 2, member_ids: repeated u64 = 3, name = 4, owner_id: u64 = 5,
   created_at: u64 = 6}
DmReadState{dm_id: u64 = 1, last_read_id: u64 = 2, mention_count: u32 = 3, last_message_id: u64 = 4}
Message gains: dm_id: optional u64 = 16
```
- **`Dm`:** `member_ids` are the current members in the order they joined (a 1:1 DM: both accounts, even after one of them has left the space). `name` (0–100 bytes, § 6.8's name rules) and `owner_id` are set for `GROUP` only (otherwise empty and 0). A `Dm` carries nothing that differs per member; what a member has seen of it is in its `DmReadState`.
- **DM ids and DM message ids** are their own id spaces (`dms` and `dm_messages` rows, § 7.1): increasing in commit order, never reused, but not comparable with channel or channel-message ids (§ 6.9's "unique space-wide" is about channel messages), so clients and the server key a DM message by (`dm_id`, `id`). A DM `Message` has `dm_id` set and `channel_id` 0, never a `thread_id`, never `pinned`, and `mentions` holds only `account_ids`. Its other fields mean what § 6.9 says. Such a `Message` is only ever sent in personal events and in DM responses to minor-10 sessions; no space `Event` carries one.
- **`DmReadState`** works like `ReadState` (§ 6.9) for one DM and one account: `last_message_id` is the newest message of the DM that account can see (withheld messages, below, are not), and it orders the account's DMs (`list_dms`, the personal snapshot). In a 1:1 DM every message from the other account counts toward `mention_count`; in a group DM only those that mention the account.

**Commands** (§ 6.8 numbering rules continue):

| # | Kind | Fields | Allowed for | Reply |
|---|---|---|---|---|
| 68 | `open_dm` | `account_id` | members, not bots; `rate_profile_*` | `created_id` (the DM's id; the existing one for that pair, if any) |
| 69 | `create_group_dm` | `account_ids` (1–9, the others), `name?` | as 68 | `created_id` |
| 70 | `add_dm_member` | `dm_id`, `account_id` | a member of the group; `rate_profile_*` | `Ack` |
| 71 | `remove_dm_member` | `dm_id`, `account_id` | the group's owner; `rate_profile_*` | `Ack` |
| 72 | `leave_dm` | `dm_id` | a member of the DM; `rate_profile_*` | `Ack` |
| 73 | `update_dm` | `dm_id`, `name` | a member of the group; `rate_profile_*` | `Ack` |
| 74 | `send_dm_message` | `dm_id`, `content`, `reply_to?`, `attachment_ids` | a member of the DM; `rate_message_*` | `created_id` |
| 75 | `edit_dm_message` | `dm_id`, `message_id`, `content` | its author; `rate_message_*` | `Ack` |
| 76 | `delete_dm_message` | `dm_id`, `message_id` | its author; from M12 `rate_message_*` | `Ack` |
| 77 | `add_dm_reaction` | `dm_id`, `message_id`, `emoji: EmojiRef` | a member of the DM (custom emoji: also `USE_CUSTOM_EMOJI` in base permissions); `rate_message_*` | `Ack` |
| 78 | `remove_dm_reaction` | `dm_id`, `message_id`, `emoji: EmojiRef` | a member of the DM, own reactions only; from M12 `rate_message_*` | `Ack` |
| 79 | `mark_dm_read` | `dm_id`, `message_id` (0 = nothing read) | a member of the DM | `Ack` |
| 80 | `block` | `account_id` | members | `Ack` |
| 81 | `unblock` | `account_id` | members | `Ack` |

**Requests** (§ 6.9's reservations):

| # | Kind | Fields | Allowed for | Reply (`Response.kind`) |
|---|---|---|---|---|
| 19 | `dm_history` | `dm_id`, `oneof anchor{before: u64; after: u64; around: u64}`, `limit` (1–100) | a member of the DM | `messages` (as `message_history`, 6 KiB reserved per message) |
| 20 | `list_dms` | `before_message_id?`, `before_dm_id?` (the last page's last entry; both or neither), `limit` (1–100) | members | `dms: DmList{dms: repeated Dm = 1, has_more: bool = 2, read_states: repeated DmReadState = 3} = 14` (the account's DMs, closed 1:1s excluded, most recently active first by its own `DmReadState.last_message_id`, then `id`, with their read states; 512 B reserved per DM) |

`fetch_attachment` and `attachment_url` (§ 6.9) also serve the attachments of DM messages, to minor-10 sessions of the DM's members who are members of the space and can see that message (a withheld one is `NOT_FOUND` to the blocker). A signed `attachment_url` follows § 6.5 here too: it is checked only against its signature and expiry, so it keeps working up to 10 minutes after it was issued, even once its holder leaves or is removed from the group DM, or leaves the space. `upload_attachment` and `upload_url` are unchanged: a DM file is an ordinary pending attachment until `send_dm_message` takes it, and it counts against `quota_account_bytes` and `quota_space_bytes` like any file (§ 6.5).

**Personal events** (`PersonalEvent.kind`, § 6.3):

| # | Kind | Message | Delivered to |
|---|---|---|---|
| 2 | `dm_updated` | `DmUpdated{dm: Dm = 1}` (full form) | a group's members (a new group, a member change, a rename; an added member gets it too); a 1:1's account it opens or reopens for (§ 6.17 "1:1") |
| 3 | `dm_removed` | `DmRemoved{dm_id: u64 = 1}` | an account that left, was removed from, or closed the DM |
| 4 | `dm_message_created` | `MessageCreated` (§ 6.9; its `Message` has `dm_id`) | the DM's members, except a blocker in a 1:1 (Blocking, below) |
| 5 | `dm_message_updated` | `MessageUpdated` (an edit or the tombstone; full form) | as 4 |
| 6 | `dm_message_deleted` | `DmMessageDeleted{dm_id: u64 = 1, message_id: u64 = 2}` | as 4 |
| 7 | `dm_reaction_added` | `DmReactionAdded{dm_id: u64 = 1, message_id: u64 = 2, emoji: EmojiRef = 3, account_id: u64 = 4}` | as 4 |
| 8 | `dm_reaction_removed` | `DmReactionRemoved{` as 7 `}` | as 4 |
| 9 | `dm_read_state` | `DmReadState` | the account's own sessions, when `mark_dm_read` changes it |
| 10 | `block_updated` | `BlockUpdated{account_id: u64 = 1, blocked: bool = 2}` | the blocking account's own sessions |

As with channels, read-state changes that follow from messages are not sent: each session derives them from `dm_message_created`. Kinds start at 2, since `PersonalEvent.seq` is field 1.

**Typing:** `StartTyping` gains `dm_id: optional u64 = 3` (with `channel_id` 0), under § 6.9's typing limits (the throttle per DM, the account's share counting its channel and DM typings together), to a member of the DM outside a timeout. It reaches the other members' minor-10 sessions as the `typing` ephemeral (§ 6.9), which gains `dm_id: optional u64 = 4` (with `channel_id` 0); never a blocker's in a 1:1.

**Rules**
- **Who:** both sides of a DM are members of the space and not bots; a bot session sending any command or request of this section gets `FORBIDDEN`, and naming a bot, a non-member or oneself is `INVALID`, as are `add_dm_member`, `remove_dm_member` and `update_dm` on a 1:1, a duplicate id in `create_group_dm`, and a `StartTyping` with both `channel_id` and `dm_id`. A member under a timeout (§ 6.12) may not send, edit, react, open or create DMs, add members or rename (`FORBIDDEN`), as in channels.
- **1:1:** at most one per pair of accounts. `open_dm` returns it if it exists (reopening it for the actor if closed), else creates it with both accounts as members and a read state for each at 0 (nothing read, so the first message is unread); it appears for the actor at once (`dm_updated`) and for the other account, as closed until then, with the first message delivered to it. `leave_dm` on a 1:1 closes it for the actor only (`dm_removed`): history and read state stay, and a later message delivered to the actor reopens it (`dm_updated`, then the message).
- **Groups:** at most 10 members (`CONFLICT` past it), and an account is in at most 100 group DMs (`CONFLICT`; accepted: it tells the adder only that the target is in 100 groups). Any member may add members and rename; only the owner removes others. Naming a current member is no `INVALID` on either: `add_dm_member` of one is acknowledged without a change, and `remove_dm_member` removes one even if it is no longer a member of the space. An account that blocked the actor is silently left out: `create_group_dm` creates the group without it and `add_dm_member` is acknowledged without a change, so a blocked account cannot pull its blocker into groups. It can infer the block from the group's member list; that is accepted, as the `CONFLICT` above is. A member who leaves or is removed gets `dm_removed` and loses access at once (a signed file URL issued before keeps working until it expires, § 6.5); when the owner leaves, ownership passes to the member who joined earliest; when the last member leaves, the group is deleted and housekeeping removes its messages (§ 7.2). A 1:1 never becomes a group: adding a third person means creating a group DM.
- **Blocking:** `block` keeps an account's list of blocked accounts (at most 1,000, `CONFLICT`), synced to its own sessions (`block_updated`, the personal snapshot); blocking oneself, a bot or a non-account is `INVALID`; blocking twice, or unblocking someone not blocked, is acknowledged without an event. A block is never revealed to the blocked account by any 1:1 behaviour (the group member list aside, Groups above). In a 1:1 where either side blocked the other, the blocked side's commands answer as usual, but: its new messages and its reactions are committed and withheld from the blocker (it sees them in its own sessions and history as usual); its edits and deletes apply as usual but reach the blocker's sessions as no event (the blocker sees the current form, or the tombstone, when it next loads that message); its typing is not sent to the blocker (one checked before the block reaches the hub is dropped too). The blocker's view is computed for the blocker: withheld messages and reactions are never delivered to its sessions, left out of its `dm_history` and reaction counts, its `DmReadState` (`last_message_id`, `mention_count`) and so its DM order, are `NOT_FOUND` to it (attachments included), and do not reopen the DM for it. They stay withheld after an unblock, and so does a later reply to one. The 20 distinct reactions per message count withheld ones too, so no account ever sees more than 20; a blocker can then be refused on a message that shows it fewer, which tells it only of activity its own block hid, which emoji included (accepted, as the group member list above). A withheld message keeps its mentions, the blocker's too, as its author wrote it; a blocker's `mention_count` and anything else that reads mentions leaves withheld messages out. Group DMs ignore blocks on the server, apart from adding (Groups, above): the blocker's client hides the blocked members' messages there from the synced list, and anyone may leave a group. Blocks have no effect in the space's channels.
- **Membership:** when a member leaves the space or is kicked, banned or erased (§ 6.8, § 6.12, § 6.13), the same writer job removes it from every group DM (as `leave_dm`, ownership passing on; the others get `dm_updated`) and deletes its DM read states, its notification settings and its push registrations (§ 6.18); its sessions close as § 6.12 says, and its personal ring entries are dropped. Its 1:1 DMs stay for the other side: their history remains readable, and sending to an account that is no longer a member is `FORBIDDEN`. A returning member finds its 1:1 DMs again (the pair's row, read states starting at 0), not the group DMs. This is the one statement of the rule; § 6.12 and § 6.13 refer to it.
- **Check order** is § 6.8's: a DM the actor is not a member of, and a message not in that DM, are `NOT_FOUND`, the same reply as a missing id. Checks on DM messages run inside the writer job that commits the change (`BEGIN IMMEDIATE`), membership and blocks included, as § 6.9 does for channels.
- **Text and limits:** as § 6.9: `content` 1–4,000 bytes (0–4,000 with an attachment), at most 10 attachments, 20 distinct reactions per message; `reply_to` names a message of the same DM. Mentions: only `<@account_id>` of the DM's current members counts, never the author's own (§ 6.9; so a group's badge index holds only others' messages); other tokens stay plain text.
- **Read states:** being added to a group, or creating one, starts the account's read state at the group's newest message; a 1:1 starts both at 0 (above). `mark_dm_read` may name any message of the DM the account can see, or 0. DM read states are held in memory while the account has a session, in the same copy as channel read states (§ 6.9) but keyed by target (channel or DM), since DM ids and channel ids overlap: the copy holds those of the account's 500 most recently active DMs (the personal snapshot's, loaded in its sequenced step), and loads another DM's, as a sequenced step of its own, when the account first marks it read. A message in a DM outside the copy changes nothing in memory: the store is authoritative for it, and the author's own message marks the author's stored read state up to it in the send's transaction (in the copy too, when it holds the DM, as in a channel). `mark_dm_read` has no rate bucket and no timeout check; a change goes to every session of the account as `dm_read_state`, the marking one included. `mention_count` counts at most 1,000 ids, as § 6.9's; a listing (the personal snapshot and `list_dms`) reads at most the newest 100 per DM, so a snapshot of 500 DMs with 1,000 unread each holds the writer for tens of milliseconds, not over half a second (#394); a DM whose badge a listing cut off (more than 100 unread) shows at most 100 until its mark reaches the oldest id kept, by `mark_dm_read` or the account's own message (what is below it is not known). Closing a 1:1 keeps its mark, which is written as usual; leaving a group drops it. They are written back with the channel ones, coalesced (§ 7.2), in their own statement, which carries the DM membership's generation and writes the mark only while that same membership exists: a mark taken before a removal never lands, even after the account is added back.
- **No moderation and no search:** DMs have no moderators; `MANAGE_MESSAGES` does not apply, and there is no pinning. DM content is not indexed for search in M10 (no FTS table), and `search` never returns a DM message.
- **Rates:** messages and edits take the sender's `rate_message_*` bucket and reactions too, shared with channels; from M12 deletes and removed reactions take it as well, before their checks, so a no-op one is still paced (#431); `open_dm`, `create_group_dm`, `add_dm_member`, `remove_dm_member`, `leave_dm`, `update_dm`, `block` and `unblock` (and § 6.18's settings and push registration) take `rate_profile_*` (§ 5), before their checks whatever the outcome.
- **Not audited:** DMs are not space administration, so nothing in this section writes an audit entry.
- **Content in logs:** DM content, names and edit text follow § 6.9: never in logs, `Error.message` or metrics. Who DMs whom is metadata of the same kind: DM ids together with account ids, DM member lists and block relationships never appear in logs or as metric labels (counts only). Hand-written redacting `Debug` for `Dm`, `CreateGroupDm`, `UpdateDm`, `SendDmMessage` and `EditDmMessage` (the messages that contain these, `PersonalEvent`, `PersonalSnapshot` and `DmList` included, inherit it).

### 6.18 Notifications and push (M10)

Notification settings per space, channel and DM, synced to every device of an account on the personal stream (§ 6.3), and mobile push: a content-free wake-up for a device that is not connected (§ 12.2, decided (a)). Push is off by default: until an admin turns it on (`push_enabled`, § 5) the server builds no HTTP client, queues nothing and makes no outbound connection (CLAUDE.md "no third-party calls by default"). Conventions as § 6.8; everything here needs minor 10 (§ 6.7).

**Objects**
```
enum NotifyTarget{NOTIFY_TARGET_UNSPECIFIED = 0, SPACE = 1, CHANNEL = 2, DM = 3}
enum NotifyLevel{NOTIFY_LEVEL_UNSPECIFIED = 0, ALL = 1, MENTIONS = 2, NONE = 3}
NotificationSetting{target: NotifyTarget = 1, target_id: u64 = 2, level: NotifyLevel = 3, muted_until: u64 = 4}
WebPushTarget{endpoint = 1, p256dh: bytes = 2, auth: bytes = 3}
RelayTarget{token: bytes = 1}
PushInfo{vapid_public_key: bytes = 1, relay: bool = 2, registered: bool = 3}
Welcome gains: push_info: optional PushInfo = 8
Capability gains: PUSH = 1
```
- **`NotificationSetting`:** `target_id` is the channel (a category too) or DM id, 0 for `SPACE`. `level` `UNSPECIFIED` means "inherit"; `muted_until` is a unix time (0 = not muted; a far-future value mutes until changed). A `target` or `level` outside the values above is `INVALID`.
- **`PushInfo`** is in the `Welcome` of a member session that negotiated `PUSH`: `vapid_public_key` is the server's VAPID key (RFC 8292), 65 bytes, uncompressed P-256; `relay` says whether a relay is configured; `registered` whether this device has a registration. A client compares the key on every connect and registers again when it changed or when `registered` is false, so a registration the server deleted (Answers, Cleanup, below) comes back at the next connect.

**Commands** (§ 6.8 numbering continues after § 6.17):

| # | Kind | Fields | Allowed for | Reply |
|---|---|---|---|---|
| 82 | `set_notification_setting` | `setting: NotificationSetting` | members, not bots; `rate_profile_*` | `Ack` |
| 83 | `register_push` | `oneof target{web_push: WebPushTarget = 1; relay: RelayTarget = 2}` | members, not bots, with `PUSH` negotiated; `rate_profile_*` | `Ack` |
| 84 | `unregister_push` | (none) | as 83 | `Ack` |
| 85 | `go_background` | (none) | as 83, without the rate token | `Ack` |

**Personal event** (§ 6.17's table continues): `notification_setting_updated: NotificationSettingUpdated{setting: NotificationSetting = 1} = 11`, to the account's own sessions. `PersonalSnapshot` gains `notification_settings: repeated NotificationSetting = 5` (at most 1,000 × ~20 B ≈ 20 KB, so a personal snapshot stays under about 140 KB, § 6.3).

**Settings**
- **Storing:** `set_notification_setting` stores the setting for its target, or deletes it (back to inherit) when `level` is `UNSPECIFIED` and `muted_until` is 0. A channel the account cannot see, or a DM it is not a member of, is `NOT_FOUND`; `SPACE` with a `target_id` other than 0, or an `UNSPECIFIED` target, is `INVALID`. At most 1,000 settings per account (`CONFLICT`). A change that changes nothing is acknowledged without an event. It shares the `rate_profile_*` bucket: a client mutes a category or the space rather than each channel.
- **Effective level** of a message for an account: for a DM, the DM's setting, else the default `ALL`; for a channel message (a thread's: its channel's), the first setting whose `level` is not `UNSPECIFIED`, walking from the channel up its parents (a voice subchannel's parent voice channel, then the category, § 6.8), else the space's, else the default `MENTIONS`. A mute (`muted_until` in the future) on the DM, or on the channel, any of its parents or the space, silences it whatever the level.
- **What counts as a mention** here: as § 6.9 (the account, a role it holds, `@everyone`), except `@here`, which means "those online now" and so never wakes a device; in a 1:1 DM every message from the other account; in a group DM `<@account_id>` of the account.
- **Desktop notifications** are the client's decision, from the synced settings and the events it already receives (`message_created` with its `mentions`, the personal DM events). No event carries a per-recipient flag.
- **Lifetime:** a setting is deleted with its target (a deleted channel, a group DM the account leaves or is removed from) and with the membership (§ 6.17 "Membership", erasure). Each deletion that leaves the account a member publishes `notification_setting_updated` with that target, `level` `UNSPECIFIED` and `muted_until` 0 ("inherit"), so a client that resumes the personal stream after a space snapshot holds no setting the server no longer has. Closing a 1:1 keeps its setting, as it keeps the read state. One whose channel the account can no longer see stays, inert; when that channel is deleted, its holder is sent "inherit" like any other, so it learns that the channel went (one bit about an id it already holds).

**Push**
- **Capability.** `PUSH` is the first `Capability` value (§ 6.2). The server lists it in `Hello` only while `push_enabled` is on; a client lists it when it can register. Commands 83–85 without it negotiated are `CONFLICT` (fixed text "push disabled").
- **One registration per instance and device, unlinkable.** Registrations are per (account, `device_pub`) of the session; a new one replaces the device's earlier one, and `unregister_push` deletes it. Instances must not be able to correlate a person through push (§ 6.2, per-instance identity): a client registers a separate UnifiedPush registration for each instance (its own endpoint and key pair per `server_id`), and a relay token is issued by the relay for one instance and device (random, or encrypted with a fresh nonce), never a raw APNs device token. The server stores what it is given and cannot check this; it is a client and relay rule.
- **Registration checks**, in order: the rate token, `PUSH`, then the target. A `web_push` target needs an `https` `endpoint` of at most 2,048 bytes with no user info, on port 443 unless `push_allowed_hosts` names that host and port, whose host, if an IP literal, passes the address rule below; `p256dh` a valid uncompressed P-256 point (65 bytes) and `auth` 16 bytes (RFC 8291). A `relay` target is an opaque token of 1–512 bytes, `CONFLICT` while no `push_relay_url` is set. Any other target, none set included, is `INVALID` with one fixed text, whatever was wrong. No name is resolved at registration: that happens at every send, in the push task. The registration's writer job reads the account's notification settings in the same transaction, and its commit result carries them, so the hub holds them from that apply step on.
- **Who gets a wake-up.** When a channel message or a DM message commits, in the apply step the hub picks the accounts that (1) have a registration for a device that wants push (below), (2) can read the message (a DM: its members, the blocker of a 1:1 not for a withheld message; a channel: the readers the hub computes for fan-out, § 6.9, § 6.11, with the account's actual voice presence, so chat gated by voice presence wakes only a device whose account is in that voice channel from another device), (3) are not its author, and (4) whose effective level says so (`ALL`, or `MENTIONS` and the message mentions them) without a mute. For each such device it `try_send`s one wake-up request to the push task. The hub holds in memory the settings of every account with a registration (loaded at start and by `register_push`, changed in apply steps, dropped with the last registration) and takes permissions and role mentions from the per-member cache (§ 8.4), so no recipient costs a database read; a DM's commit result carries its member ids. Blocks matter only as § 6.17 says (withheld 1:1 messages); they do not filter channel or group-DM wake-ups.
- **Which devices want push.** A device wants push when it has no live session, or when its live session has sent `go_background`. A client that registers push sends `go_background` when it goes to the background, keeps reading until the `Ack`, then closes its session (QUIC `CONNECTION_CLOSE`), keeping its resume token (§ 6.3) for a cheap reconnect; after a wake-up it does the same once it has synced. Everything committed before the `Ack` reached the session; everything after it wakes the device. The flag lasts until the session ends: a client that comes back to the foreground connects again rather than reusing the session. When a session ends without `go_background` (a timeout, a lost connection) and the hub skipped a wake-up for that device because the session was live, the device gets one wake-up when the session ends.
- **Coalescing** lives in the push task: per device at most one wake-up in flight and at most one per 30 s; triggers inside the window fold into one, sent when it ends. The hub tells the push task when a registered device connects again (over the same queue; losing that hint to a full queue costs one extra wake-up), and a held-back wake-up for that device is then dropped.
- **The wake-up** (Web Push): an RFC 8030 `POST` to the endpoint, encrypted by RFC 8291 (`aes128gcm`, one record) for the registration's `p256dh` and `auth`, with the fixed 12-byte plaintext `{"yapsta":1}`: no content, sender, channel, DM, account, name or count. Headers: `TTL: 3600`, `Urgency: high`, `Content-Encoding: aes128gcm`, and `Authorization: vapid t=<JWT>, k=<public key>` (RFC 8292; ES256, `aud` the endpoint's origin, `exp` 12 h ahead, cached per origin and reused while more than 1 h of it is left, at most 1,024 origins cached; `sub` = `push_vapid_subject` when set). The record size in the `aes128gcm` header is 4,096, and each wake-up has a fresh ephemeral key and salt. An origin is written one way for the `aud`, the token cache and a 429's pause: `https://`, the host lowercased without a trailing dot (an IPv6 address in brackets), and `:port` only when it is not 443. The client learns what arrived by connecting.
- **The relay** (iOS): an `https` `POST` to `push_relay_url` with the JSON body `{"token":"<the registration's token, base64url>"}` and nothing else, plus `Authorization: Bearer <push_relay_key>` when set. The relay sees that token, the server's address and the timing, nothing more. Running a relay needs the app publisher's APNs key: it is the publisher's service, not part of this server.
- **Answers:** a 2xx is success. From a push endpoint, 400, 401, 403, 404, 410 and 413 delete the registration (401 and 403 also follow a replaced VAPID key, after which clients register again, above). From the relay, only 404 and 410 delete it; its other errors are failures. 429 pauses that endpoint's origin (or the relay) until its `Retry-After` in seconds (at most 1 h; 60 s when it is missing or a date). Anything else, and a timeout, drops that wake-up: nothing is retried, and the next trigger tries again. A push endpoint registration (not the relay's: it is the operator's one origin, covered by the 429 pause) that fails 3 times in a row rests: its wake-ups are skipped, and counted as `paused`, for 30 s, doubling on each later failure to at most 15 min (#430). A success or a deleting answer ends the rest, a 429 leaves it, and a new registration version starts clean; failing never deletes a registration. The state is in memory only, bounded by the registrations, and never logged.
- **Egress rules** (every push request): `https` only; TLS 1.3 only, with the server's one rustls crypto provider, verified against the operating system's roots (`rustls-native-certs`, which honours `SSL_CERT_FILE` and `SSL_CERT_DIR`); with no root loaded, every push request fails (closed, counted). The host is resolved (the system resolver, at most 16 lookups at once; a lookup cannot be cancelled, so one that outlives its request keeps its place until it returns), and every address must lie in a global unicast range (an allow-list of global ranges, not a deny-list: no loopback, private (RFC 1918, RFC 4193), link-local, CGNAT 100.64.0.0/10, multicast, unspecified, reserved, documentation or benchmarking address); an IPv6 address that embeds an IPv4 one (v4-mapped `::ffff:0:0/96`, v4-compatible `::/96`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`) is judged by that IPv4 address. Otherwise only `2000::/3` can be global, less `2001::/23` (IETF protocol assignments, Teredo among them), `2001:db8::/32` and `3fff::/20` (documentation); the local-use NAT64 prefix `64:ff9b:1::/48` lies outside it and is refused whole, since where its IPv4 address sits depends on the operator's prefix length. `push_allowed_hosts` lifts this for the hosts and ranges it names (an IPv6 address with a port is written `[addr]:port`). Port 443 only, for endpoints and `push_relay_url` alike, unless `push_allowed_hosts` names that host and port. The connection goes to an address that was checked, on the URL's port (the checked addresses with the families alternating, the resolver's first family first (RFC 8305 § 4), each attempt within an even share of a connect budget that ends three quarters of the bound after the request began (resolution included) and at most a quarter of it, so dead addresses leave time for the next and a broken IPv6 route reaches IPv4 second); proxy environment variables are ignored; the request's `Host` and framing headers are the client's own; redirects are not followed (a 3xx is a failure); 10 s for the whole request; only the answer's status line and headers are read (at most 8 KiB in all, interim 1xx answers included, and 32 header lines), never its body. A host name TLS could not verify (an empty or over-long label, a leading hyphen) or an explicit port that is not digits for a number from 0 to 65535 fails the URL check, at registration as at a send; an empty path is sent as `/`.
- **The push task** runs apart from the commit → apply → publish path: a bounded queue of 1,024 (full: the request is dropped and counted), at most 16 requests in flight, at most 2 of them for one account (#430: wake-ups over that stay held as above, the task keeps reading its queue, and only the 16 stop it; one person with k accounts can still hold 2k, for as long as the rest above lets dead targets hold them), its crypto inline (one ECDH, about 100 µs, per wake-up; the JWT is cached; at most 16 in flight and coalesced per device, so it stays small enough not to need a blocking thread). At shutdown it waits at most 5 s for requests in flight, then abandons them. A slow or dead endpoint never delays a commit or a delivery.
- **Cleanup:** a registration goes when its device leaves the account's device list or expires (checked when a newer list is stored, and hourly), with the membership (§ 6.17 "Membership"), on erasure, and at a start with `push_enabled` off (clients register again when `PUSH` comes back).
- **Registration versions:** every stored registration has a version, taken from a counter that is never reused, and a replacement gets a new one. The hub keeps the current registrations (device, version, target) in memory, in a map shared with the push task that only apply steps write (the push task only reads it; the hub never waits on the push task); queued and held-back wake-ups name only (account, device, version), and the push task reads the target from that table just before each request and drops the wake-up when the device's current version differs or is gone, so after a removal or replacement at most a request already being sent goes out with the old registration. An answer that deletes a registration (Answers, above) deletes it only if its version is still the one the request used, through a writer job like any change.
- **Metrics** count wake-ups by outcome with fixed labels (sent, dropped, coalesced, gone, paused, failed), never with an endpoint, host or account.
- **Secrets and logs:** endpoints, `p256dh`, `auth`, relay tokens, the VAPID private key and `push_relay_key` never appear in logs, `Error.message`, metrics or the audit log. Push failures are logged and counted by outcome only: the HTTP client's errors and the answer's body are never formatted into a log line. Hand-written redacting `Debug` for `WebPushTarget`, `RelayTarget`, `RegisterPush`, the push task's request and the registration row type; `NotificationSetting` and the messages carrying it (ids beside their account, § 6.17 "Content in logs") get one too. The VAPID key is generated on the first start with push on, into `secrets/push_vapid.key` (mode 0600, § 5, § 7.6), and held in a redacting, zeroizing type.

---

