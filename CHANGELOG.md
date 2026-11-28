# Changelog

Notable changes to `yapsta-proto`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions are
`MAJOR.MINOR.PATCH` with MAJOR the protocol's ALPN major (`yapsta/1`), MINOR
the newest protocol minor this crate defines (`MINOR_VERSION`) and PATCH every
other release (README.md, Versioning).

## [Unreleased]

### Fixed

- PROTOCOL.md § 6.19: `device_lists` also returns the caller's own list when it
  names itself, as servers already do; a device needs its own account's list.

## [1.11.2] - 2026-11-27

### Added

- `UploadAttachmentRequest.encrypted` and `UploadUrlRequest.encrypted`
  (field 2 of each): an upload a client encrypted for an MLS DM, stored as
  `application/octet-stream`, never sniffed or thumbnailed, at the client's
  padded size, under the same caps, quotas, free-disk floor and rate
  (PROTOCOL.md § 6.5 "Encrypted uploads", § 6.19 "Attachments"). An MLS DM
  message takes only the sender's encrypted uploads (at most 10, thumbnails
  included); a channel or plaintext DM message naming one is `INVALID`.
  Golden examples of both paths; a plaintext upload's bytes are unchanged.
- `request_mls_rejoin` (command 90), `RequestMlsRejoin` and
  `MlsRejoinReason` (`LOST_STATE`, `FORK`; open): a device that lost its MLS
  state, or whose group forked, asks the members to add it again with a
  fresh KeyPackage (PROTOCOL.md § 6.19 "Rejoining"). `MlsEntry.entry` gains
  `rejoin_requested` (8), `MlsRejoinRequested`, which the group's other
  devices get. The server's checks and effects, the members' response and
  the rate limits (per device and DM 3 an hour, burst 2; per DM and account
  10 a day) are in § 6.19. § 6.19 "Delivery and the log" also says a client
  acknowledges an entry whose kind it does not know. Additive within minor 11, under `MLS_DMS`.
- Redacting `Debug` for both new messages (the KeyPackage by length, never
  the asking account or device); a golden example of each, the command's
  minor and metrics name, and the reasons' numbers.
- `DmContent`, the plaintext inside an MLS DM's ciphertext (PROTOCOL.md
  § 6.19 "Content"): a sender-chosen 16-byte `id` and one body (`DmText`,
  `DmEdit`, `DmDelete`, `DmReaction`, `DmGroupName`), with
  `EncryptedAttachment` and `EncryptedThumbnail` for files' keys, digests,
  names and types. The sender's padding recipe and the receiver's drop
  rules are in § 6.19. Additive, within minor 11: `MINOR_VERSION` stays 11,
  and the server never decodes it.
- `DmMessageKind.DM_MESSAGE_KIND_GROUP_NAME = 5`, the clear kind of a group
  DM's name change.
- `Message.delete_id` (field 20): on an MLS DM's `DELETE`, the server id of
  the message it dropped, so a receiver can check the delete's inner target.
  § 6.19 also fixes what `Message.attachments` holds for an MLS DM (only
  each upload's `id` and padded `size`).
- Redacting `Debug` for every new message (lengths and counts only; a
  file's size and a custom reaction's emoji id not at all); tests
  for each body's round trip and committed bytes, an unknown body and emoji
  kind, the kinds' numbers and the `Debug` output; a golden example of
  `GROUP_NAME`.

### Changed

- PROTOCOL.md § 6.19 "Commits": only the account a step adds (every member at
  epoch 0) must hold a leaf after the commit, so a member whose devices all
  lapsed no longer blocks every commit; a Remove may also name a leaf whose
  certificate has expired; clients renew their leaf certificate in a path or
  Update. "Adding an account": an `add_dm_member` to an MLS group that cannot
  apply is one reason-neutral `INVALID`, never acknowledged. Documentation
  only; no wire change.

## [1.11.1] - 2026-11-24

Protocol minor 11, part 2: end-to-end encrypted DMs with MLS, behind
`Capability.MLS_DMS` (PROTOCOL.md § 6.19).

### Added

- `CAPABILITY_MLS_DMS = 2`; commands `reserve_dm` (86),
  `publish_key_packages` (87), `submit_mls_commit` (88) and `ack_mls` (89); requests
  `device_lists` (21), `claim_key_packages` (22) and `mls_log` (23) with
  their responses (15–17); the server-only `Envelope.body` `mls`
  (`MlsDelivery`, 21).
- `DmEncryption`, `DmMessageKind`, `MlsCommit`, `MlsEntry`,
  `MlsExternalSender` and the KeyPackage and device-list messages.
- Fields: `Dm` 7–9 (`encryption`, `successor_dm_id`, `mls_group_id`),
  `Message` 17–19, `SendDmMessage` 5–7, `OpenDm` 2–3, `CreateGroupDm` 3–4,
  `AddDmMember` 3, `Error.mls_epoch` (5), `Welcome.mls_external_sender` (9).
- Redacting `Debug` for every new message with MLS bytes or a lookup
  target; golden examples and minor checks for every new kind.

## [1.11.0] - 2026-11-24

Protocol minor 11, part 1: DM modes. A server built on this release sends
`Hello.versions = [11, 10]` and accepts both.

### Added

- `DmMode` (`UNSPECIFIED`, `OFF`, `LIVE`, `STORED`) and `Space.dm_mode`
  (field 15), in both forms of `Space` and in `space_updated` (PROTOCOL.md
  § 6.17, "DM modes"). `OFF` refuses new DM activity with `FORBIDDEN` and keeps
  history readable, leaving and deleting; `LIVE` is reserved for encrypted live DMs and is never sent
  yet.
- `AuditAction.DM_MODE_CHANGED = 38`: the operator changed the DM mode,
  `value` = the new `DmMode` number (PROTOCOL.md § 6.12, § 6.17).
- Tests: a golden example per new value, the enum's numbers, its `Debug`
  names, and the encoding of a `Space` without field 15.

### Changed

- `MINOR_VERSION` is 11 and `SUPPORTED_MINORS` is `[11, 10]`: minor 9 is no
  longer accepted (PROTOCOL.md § 6.7).

## [1.10.0] - 2026-11-23

The first release from this repository. `yapsta-proto` moved here from the
Yapsta server repository (`crates/proto`), with its history; the code is the
server's at the move, protocol `yapsta/1` minor 10, accepting minors 10 and 9.

### Added

- `COMMAND_KIND_NAMES` and `command_kind_index`: an exhaustive index over the
  command kinds, for counting commands in a fixed table. Rust API only; the
  wire is unchanged.
- `PROTO_SOURCE` and `WIRE_SURFACE`: the `.proto` source and the committed
  wire surface as text, for consumers' tests.
- A decoded-size bound (§ 6.1): `frame::decoded_bound` walks an encoded
  `Envelope`, before decoding and without allocating, for the most heap it
  can decode to, and `FrameCodec` refuses a frame over its stream's decoded
  limit as `TOO_LARGE`: `MAX_CONTROL_DECODED` (16 MiB),
  `MAX_REQUEST_DECODED` (64 MiB) and, while restricted,
  `MAX_RESTRICTED_DECODED` (256 KiB). `FrameCodec::with_decoded_limit` and
  `decoded_limit` set and read a codec's; `FrameCodec::with_limit` takes 16
  times the frame limit. `frame::repeated_entries` counts a repeated field's
  entries before decoding, for per-kind caps; `frame::MAX_DEPTH` is how deep
  the walk follows nested messages. The wire is unchanged.
- The protocol specification, `docs/PROTOCOL.md` (§ 6.1 to § 6.18, numbered
  as before). § 6.13, the operator's side (admin HTTP API, operator CLI), is
  server-specific and stays in the server's documentation; § 6.13 here says so.

### Changed

- Licensed Apache-2.0.
