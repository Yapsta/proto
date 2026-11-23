#!/usr/bin/env bash
# Release checks for .github/workflows/release.yml, runnable locally too.
#
#   scripts/release.sh check VERSION   VERSION is X.Y.Z, Cargo.toml's version,
#                                      has a CHANGELOG.md entry and is not
#                                      tagged yet; prints the previous release
#                                      tag (empty for the first)
#   scripts/release.sh notes VERSION   prints VERSION's CHANGELOG.md entry
#   scripts/release.sh self-test       checks the above against this tree
set -euo pipefail
cd "$(dirname "$0")/.."

fail() {
    echo "::error::$*" >&2
    exit 1
}

cargo_version() {
    sed -n 's/^version = "\([^"]*\)"$/\1/p' Cargo.toml | head -n 1
}

# The body of `## [VERSION] - date`, up to the next `## ` heading.
entry() {
    awk -v v="$1" '
        /^## / { if (found) exit; if (index($0, "## [" v "]") == 1) { found = 1; next } }
        found { print }
    ' CHANGELOG.md
}

check() {
    local version="$1" previous
    [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "version '${version}' is not X.Y.Z (no v)"
    [ "$(cargo_version)" = "${version}" ] || fail "Cargo.toml's version is $(cargo_version), not ${version}"
    [ -n "$(entry "${version}" | tr -d '[:space:]')" ] || fail "CHANGELOG.md has no entry '## [${version}] - YYYY-MM-DD'"
    ! git rev-parse -q --verify "refs/tags/v${version}" > /dev/null || fail "v${version} is already tagged"
    # The newest version tag below this one, by version order.
    previous=$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' | sed 's/^v//' \
        | { cat; echo "${version}"; } | sort -t. -k1,1n -k2,2n -k3,3n \
        | awk -v v="${version}" '$0 == v { print p; exit } { p = $0 }')
    [ -z "${previous}" ] || previous="v${previous}"
    printf '%s\n' "${previous}"
}

notes() {
    local body
    body=$(entry "$1")
    [ -n "$(printf '%s' "${body}" | tr -d '[:space:]')" ] || fail "CHANGELOG.md has no entry for $1"
    printf '%s\n' "${body}" | sed -e '/./,$!d'
}

self_test() {
    local v
    v=$(cargo_version)
    [ -n "$(entry "${v}" | tr -d '[:space:]')" ] || fail "CHANGELOG.md has no entry for Cargo.toml's version ${v}"
    ! (check "v${v}" 2> /dev/null) || fail "check accepted a v prefix"
    ! (check "0.0.0" 2> /dev/null) || fail "check accepted a version that is not Cargo.toml's"
    notes "${v}" > /dev/null
    echo "release tooling ok (Cargo.toml ${v})"
}

case "${1:-}" in
    check) check "${2:?version}" ;;
    notes) notes "${2:?version}" ;;
    self-test) self_test ;;
    *) fail "usage: $0 check|notes VERSION, or $0 self-test" ;;
esac
