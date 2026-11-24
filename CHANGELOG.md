# Changelog

Notable changes to `yapsta-proto`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions are
`MAJOR.MINOR.PATCH` with MAJOR the protocol's ALPN major (`yapsta/1`), MINOR
the newest protocol minor this crate defines (`MINOR_VERSION`) and PATCH every
other release (README.md, Versioning).

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
