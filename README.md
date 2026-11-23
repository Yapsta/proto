# yapsta-proto

Yapsta's native wire protocol, ALPN `yapsta/1`, as a Rust crate: the protobuf
messages (`proto/yapsta/v1/yapsta.proto`, compiled with
[protox](https://crates.io/crates/protox), so no system `protoc` is needed),
the error codes, the version constants, the frame codec, the voice datagram
header and the identity primitives (seed, recovery phrase, device
credentials). No sockets and no TLS.

Yapsta Server, Yapsta Client and Yapsta Bot all build against this crate. The
specification is [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

## Depending on it

The crate is not on crates.io (`publish = false`). Depend on a release tag of
this repository:

```toml
[dependencies]
yapsta-proto = { git = "https://github.com/Yapsta/proto", tag = "v1.10.0" }
```

Pin a tag, never a branch: `Cargo.lock` then records the exact commit. With
cargo-deny's `[sources] unknown-git = "deny"`, add the repository to
`allow-git = ["https://github.com/Yapsta/proto"]`.

## The add-only rule

The wire surface only grows. Message fields and enum values are added, never
renumbered, retyped, moved into or out of a `oneof`, or reused; a retired one
is removed with its number and name reserved (PROTOCOL § 6.7).
`tests/wire_surface.rs` enforces this against the committed
`tests/wire_surface.txt`. An addition makes the test ask for the file to be
updated, so every addition is reviewed:

```sh
YAPSTA_BLESS=1 cargo test --test wire_surface
```

Blessing only ever adds lines; it refuses while anything was lost. A change
that cannot follow the rule needs a new ALPN major (`yapsta/2`).

Text and bytes fields are classified too: a message carrying a secret or user
text is listed in `redacted_debug.txt` and gets a redacting `Debug`
(`src/debug.rs`), so a stray `{:?}` cannot log it.

## Versioning

Releases are `vMAJOR.MINOR.PATCH`:

- **MAJOR** is the protocol's ALPN major: `1` for `yapsta/1`.
- **MINOR** is the newest protocol minor the crate defines (`MINOR_VERSION`).
  A release that adds a protocol minor bumps it and resets PATCH.
- **PATCH** counts every other release: fixes, documentation, and additions to
  the Rust API that leave the wire unchanged.

So `v1.10.0` is the first release that speaks `yapsta/1` minor 10.
`SUPPORTED_MINORS` lists the minors a server built on it accepts (the current
and the previous one). The Rust API keeps working across a MINOR or PATCH
bump; anything that would break it waits for a MAJOR.

Protocol changes land here first: a pull request to this repository (the
`.proto`, the code, `docs/PROTOCOL.md`, `CHANGELOG.md`), then a release, then
the server, client and bot move to the new tag.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

The Rust toolchain is pinned in `rust-toolchain.toml`. CI runs the same on
every pull request and on `main`, plus cargo-deny.

## Releasing

Releases are cut from GitHub Actions only: **Actions → Release → Run
workflow**, with the version (`Cargo.toml`'s, without the `v`), the commit
(default `main`) and optionally a dry run. The workflow checks the version
and its `CHANGELOG.md` entry, creates the tag `vX.Y.Z` and a GitHub Release
whose notes are that entry and the pull requests merged since the previous
release. Nothing else is published.

## Licence

Apache-2.0 ([LICENSE](LICENSE)).
