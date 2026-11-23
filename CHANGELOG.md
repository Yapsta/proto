# Changelog

Notable changes to `yapsta-proto`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions are
`MAJOR.MINOR.PATCH` with MAJOR the protocol's ALPN major (`yapsta/1`), MINOR
the newest protocol minor this crate defines (`MINOR_VERSION`) and PATCH every
other release (README.md, Versioning).

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
- The protocol specification, `docs/PROTOCOL.md` (§ 6.1 to § 6.18, numbered
  as before).

### Changed

- Licensed Apache-2.0.
