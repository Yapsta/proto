# yapsta-proto fuzz targets

cargo-fuzz (libFuzzer) targets for the parts of `yapsta-proto` that read
what a peer sends:

| Target | What it feeds |
|---|---|
| `frame_decode` | A byte stream, in chunks, to `FrameCodec` in each mode (client control, server control, restricted, small limit, request). Checks that frames stay within their limit and their decoded-size bound within the codec's decoded limit, that no server-only body reaches a server, that buffer growth follows the bytes received, and that frames round-trip. |
| `envelope_decode` | `Envelope::decode` of arbitrary bytes, then `carries_server_body`, `decoded_bound` and `repeated_entries` (whatever decodes has a bound), `minor_of`, the redacting `Debug` impls and the round trip. |
| `identity` | `PublicKey::from_slice`, `verify_device_list`, `ServerId::parse`, `Seed::from_phrase`, `BotSeed::from_text`, `AuthTranscript::verify`. |
| `voice_header` | `voice::Header::parse` and `voice::forwarded`. |

Run one, time-boxed (needs rustup and `cargo install cargo-fuzz`):

```sh
scripts/fuzz.sh frame_decode -max_total_time=300
scripts/fuzz.sh frame_decode fuzz/artifacts/frame_decode/crash-…   # reproduce
```

CI runs every target for 5 minutes weekly and on manual dispatch
(`.github/workflows/fuzz.yml`), never on pull requests.

`corpus/`, `artifacts/` and `target/` are git-ignored and grow quickly, so
delete them when you're done.

## Licence exception (scope: this directory only)

`libfuzzer-sys` is `(MIT OR Apache-2.0) AND NCSA`, and NCSA is not on the
licence allowlist in `deny.toml`. It is allowed for this fuzz workspace only.
This directory is its own Cargo workspace with its own `Cargo.lock`. It is
not part of the `yapsta-proto` package, and nothing that depends on the
crate builds or links it. `deny.toml` is unchanged and does not see it.
Don't depend on this crate from anywhere else.
