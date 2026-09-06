#!/usr/bin/env bash
#
# Build the release artifacts: statically linked musl binaries for x86_64 and
# aarch64, plus a SHA256SUMS file. Output lands in dist/.
#
# Why static musl, when build-x86_64.sh argues for glibc:
#   That script predates the move off PAM. Webshell no longer touches the host
#   auth stack at all — local passwords are argon2id hashes it manages itself
#   (see src/localauth.rs), so there is no dlopen, no setuid helper, and
#   nothing that a fully static binary would break. One file per architecture
#   runs on any Linux, with no glibc version to match.
#
# The one thing static musl gives up is NSS: getpwuid reads /etc/passwd
# directly rather than going through LDAP/SSSD. That resolves the login shell
# and home directory of the single account webshell runs as, which is normally
# a local account anyway; set [terminals] login_cmd if it is not.
#
#   ./build-release.sh
#
# Environment overrides:
#   ZIG_BIN   path to a zig binary (default: zig on PATH, then the musl-cross cache)
set -euo pipefail

cd "$(dirname "$0")"

TARGETS=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl)
OUT="dist"

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
echo ">> webshell $VERSION"

# 1. cargo-zigbuild does the cross-linking; plain cargo cannot link the
#    non-native musl target without a cross toolchain installed.
# (`cargo zigbuild --version` is not a thing — the subcommand rejects it — so
# probe the binary that backs it instead.)
if ! command -v cargo-zigbuild >/dev/null 2>&1; then
    echo "error: cargo-zigbuild not found. Install it with:" >&2
    echo "         cargo install cargo-zigbuild" >&2
    exit 1
fi

if [[ -z "${ZIG_BIN:-}" ]]; then
    if command -v zig >/dev/null 2>&1; then
        ZIG_BIN="$(command -v zig)"
    else
        ZIG_BIN="$(ls "$HOME"/.cache/musl-cross/zig-*/zig 2>/dev/null | head -1 || true)"
    fi
fi
if [[ -z "${ZIG_BIN:-}" || ! -x "$ZIG_BIN" ]]; then
    echo "error: no zig found. Install zig or set ZIG_BIN=/path/to/zig" >&2
    exit 1
fi
export PATH="$(dirname "$ZIG_BIN"):$PATH"
echo ">> Using zig: $ZIG_BIN ($("$ZIG_BIN" version))"

rm -rf "$OUT"
mkdir -p "$OUT"

for target in "${TARGETS[@]}"; do
    if ! rustup target list --installed 2>/dev/null | grep -qx "$target"; then
        echo ">> Adding rustup target $target"
        rustup target add "$target"
    fi

    echo ">> Building $target (release)"
    cargo zigbuild --release --target "$target"

    bin="target/${target}/release/webshell"

    # 2. Verify it really is static. A binary with a PT_INTERP segment is
    #    dynamically linked and would fail on a host without a matching loader
    #    — the exact thing these artifacts exist to avoid.
    if readelf -l "$bin" 2>/dev/null | grep -q INTERP; then
        echo "error: $bin is dynamically linked (PT_INTERP present)" >&2
        exit 1
    fi
    echo "   verified statically linked"

    # Asset names follow the convention established by earlier releases:
    # webshell-<version>-linux-<arch>-musl
    case "$target" in
        x86_64-*)  arch=x86_64 ;;
        aarch64-*) arch=aarch64 ;;
        *)         echo "error: no asset name mapped for $target" >&2; exit 1 ;;
    esac
    cp "$bin" "$OUT/webshell-${VERSION}-linux-${arch}-musl"
done

# 3. Checksums, so a download can be verified.
( cd "$OUT" && sha256sum webshell-* > SHA256SUMS )

echo
echo ">> Artifacts in $OUT/:"
ls -lh "$OUT"
echo
cat "$OUT/SHA256SUMS"
