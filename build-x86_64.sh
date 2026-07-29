#!/usr/bin/env bash
#
# Cross-build a Linux x86_64 binary of webshell locally, from any host arch,
# using cargo-zigbuild (zig as the cross linker). Output is ALWAYS
# x86_64-unknown-linux-gnu.
#
# Why glibc (gnu) and NOT static musl:
#   webshell authenticates via PAM, which it loads at runtime with
#   dlopen("libpam.so.0"). A fully static musl binary's dlopen is a stub that
#   fails, so PAM (system-password login) would silently break. A dynamically
#   linked glibc binary keeps dlopen working. This project has NO C/C++
#   dependencies, so the cross-link is trivial.
#
#   ./build-x86_64.sh
#
# Environment overrides:
#   GLIBC_VERSION   target glibc floor (default 2.36; must be <= target's glibc)
#   ZIG_BIN         path to a zig binary (default: cached zig, then PATH)
set -euo pipefail

TARGET="x86_64-unknown-linux-gnu"
GLIBC_VERSION="${GLIBC_VERSION:-2.36}"
cd "$(dirname "$0")"

# 1. Rust std for the target.
if ! rustup target list --installed 2>/dev/null | grep -qx "$TARGET"; then
    echo ">> Adding rustup target $TARGET"
    rustup target add "$TARGET"
fi

# 2. Locate zig (cargo-zigbuild needs it). Prefer an explicit ZIG_BIN, then a
#    zig already on PATH, then the cache populated by the sibling musl.sh.
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

# 3. Build. The .<glibc> suffix tells zig which glibc to target.
echo ">> Building webshell for ${TARGET}.${GLIBC_VERSION} (release)"
cargo zigbuild --release --target "${TARGET}.${GLIBC_VERSION}" "$@"

BIN="target/${TARGET}/release/webshell"

# 4. Verify: 64-bit x86_64 ELF, dynamically linked (must have PT_INTERP so
#    dlopen works at runtime).
read -r elf_class < <(od -An -tu1 -j4 -N1 "$BIN")
read -r m_lo m_hi < <(od -An -tu1 -j18 -N2 "$BIN")
elf_machine=$(( m_lo + m_hi * 256 ))
if (( elf_class != 2 || elf_machine != 62 )); then
    echo "error: $BIN is not a 64-bit x86_64 ELF (class=$elf_class machine=$elf_machine)" >&2
    exit 1
fi
echo ">> Verified x86_64 64-bit ELF"
if command -v readelf >/dev/null 2>&1; then
    if readelf -l "$BIN" 2>/dev/null | grep -q INTERP; then
        echo ">> Verified dynamically linked (PT_INTERP present) — dlopen/PAM OK"
    else
        echo "warning: $BIN has no PT_INTERP (static); dlopen/PAM will NOT work" >&2
    fi
fi
echo ">> Built $BIN"
ls -lh "$BIN"
