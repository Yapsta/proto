#!/usr/bin/env bash
# Runs one of yapsta-proto's cargo-fuzz targets (fuzz) on the
# pinned nightly. Extra arguments go to libFuzzer: a time box
# (-max_total_time=300) or a crash file to reproduce.
#
#   scripts/fuzz.sh frame_decode -max_total_time=300
#   scripts/fuzz.sh frame_decode fuzz/artifacts/frame_decode/crash-…
#
# Targets: frame_decode, envelope_decode, identity, voice_header.
# Needs rustup and `cargo install cargo-fuzz`. The corpus stays in
# fuzz/corpus (git-ignored); delete it and target/ when done.
set -euo pipefail

NIGHTLY="${NIGHTLY:-nightly-2026-11-01}"
target="${1:?usage: scripts/fuzz.sh <target> [libFuzzer args…]}"
shift

case "$target" in
  # Big enough for a frame past the 32 KiB restricted limit.
  frame_decode) max_len=70000 ;;
  envelope_decode | identity) max_len=40000 ;;
  voice_header) max_len=1300 ;;
  *) echo "unknown target: $target" >&2; exit 2 ;;
esac

# Reproducing a file: make its path absolute, cargo fuzz runs in fuzz/.
args=()
for a in "$@"; do
  if [[ "$a" != -* && -e "$a" ]]; then a="$(cd "$(dirname "$a")" && pwd)/$(basename "$a")"; fi
  args+=("$a")
done

cd "$(dirname "$0")/../fuzz"
# The toolchain's own cargo and rustc first: a rustc elsewhere on PATH (a
# system or Homebrew one) would otherwise win and refuse -Zsanitizer.
toolchain_bin="$(dirname "$(rustup which --toolchain "$NIGHTLY" rustc)")"
export PATH="${toolchain_bin}:${CARGO_HOME:-$HOME/.cargo}/bin:${PATH}"
exec cargo fuzz run -O "$target" -- \
  -max_len="$max_len" -rss_limit_mb=2048 -print_final_stats=1 ${args[@]+"${args[@]}"}
