#!/usr/bin/env bash
#
# One-time (idempotent) bootstrap of the mutable half of the environment:
#
#   $EGF_EXT/AFLplusplus   AFL++ source tree, overlaid with AFL_patches/
#   $EGF_EXT/SVF           SVF 3.0, built with the Nix LLVM 16
#   $EGF_EXT/.egf-prefix   install prefix for afl-* binaries
#
# Everything else (compilers, libs) comes from `nix develop`. Run this *inside*
# the dev shell. `--dry-run` prints the plan without touching anything.
#
set -euo pipefail

AFL_VERSION="${AFL_VERSION:-4.35c}"
SVF_BRANCH="${SVF_BRANCH:-SVF-3.0}"

DRY_RUN=0
DO_SVF=1
DO_AFL=1
RECONFIGURE=0

usage() {
    cat <<EOF
usage: bootstrap.sh [--dry-run] [--svf-only] [--afl-only] [--reconfigure]

  --dry-run      print the commands instead of running them
  --svf-only     fetch/build SVF only
  --afl-only     fetch/patch/build AFL++ only
  --reconfigure  delete \$SVF_DIR/build first (needed after the toolchain
                 changes, since CMakeCache.txt pins the old compiler paths)

environment (set by the nix dev shell, override freely):
  EGF_ROOT   ${EGF_ROOT:-<unset>}
  EGF_EXT    ${EGF_EXT:-<unset>}
  AFL_ROOT   ${AFL_ROOT:-<unset>}
  SVF_DIR    ${SVF_DIR:-<unset>}
  PREFIX     ${PREFIX:-<unset>}
  LLVM_DIR   ${LLVM_DIR:-<unset>}
  Z3_DIR     ${Z3_DIR:-<unset>}
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --svf-only) DO_AFL=0 ;;
        --afl-only) DO_SVF=0 ;;
        --reconfigure) RECONFIGURE=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[ERROR] unknown argument: $1" >&2; usage; exit 1 ;;
    esac
    shift
done

for var in EGF_ROOT EGF_EXT AFL_ROOT SVF_DIR PREFIX LLVM_DIR Z3_DIR; do
    if [[ -z "${!var:-}" ]]; then
        echo "[ERROR] \$$var is unset - run this inside 'nix develop'." >&2
        exit 1
    fi
done

run() {
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '  +'; printf ' %q' "$@"; printf '\n'
    else
        "$@"
    fi
}

log() { printf '\n\033[33m[%s]\033[0m %s\n' "bootstrap" "$*"; }
err() { printf '\033[31m[ERROR]\033[0m %s\n' "$*" >&2; }

# ------------------------------------------------------------------ SVF ----
bootstrap_svf() {
    log "SVF ($SVF_BRANCH) -> $SVF_DIR"

    if [[ -d "$SVF_DIR/.git" ]]; then
        echo "  already cloned, skipping fetch"
    elif [[ -e "$SVF_DIR" ]]; then
        # Never clone into / write over a directory we did not create.
        err "$SVF_DIR exists but is not a git checkout - refusing to touch it."
        err "Point \$SVF_DIR elsewhere, or remove it yourself."
        exit 1
    else
        run git clone --branch "$SVF_BRANCH" --depth 1 \
            https://github.com/SVF-tools/SVF.git "$SVF_DIR"
        run git -C "$SVF_DIR" submodule update --init --recursive
    fi

    if [[ $RECONFIGURE -eq 1 && -e "$SVF_DIR/build" ]]; then
        echo "  --reconfigure: discarding $SVF_DIR/build"
        run rm -rf "$SVF_DIR/build"
    fi

    if [[ -f "$SVF_DIR/build/build.ninja" ]]; then
        echo "  build dir configured, reusing (--reconfigure to start over)"
    else
        # Absolute paths, not bare names: CMake would otherwise resolve clang-16
        # via CMAKE_PREFIX_PATH and pick up the *unwrapped* clang from
        # $LLVM_DIR/bin, which cannot find stddef.h.
        local cc cxx
        cc="$(command -v clang-16)"
        cxx="$(command -v clang++-16)"

        run cmake -S "$SVF_DIR" -B "$SVF_DIR/build" -G Ninja \
            -DCMAKE_BUILD_TYPE=Release \
            -DSVF_WARN_AS_ERROR=OFF \
            -DCMAKE_C_COMPILER="$cc" \
            -DCMAKE_CXX_COMPILER="$cxx" \
            -DLLVM_DIR="$LLVM_DIR/lib/cmake/llvm" \
            -DZ3_DIR="$Z3_DIR"
    fi

    run ninja -C "$SVF_DIR/build"
}

# --------------------------------------------------------------- AFL++ ----
bootstrap_afl() {
    log "AFL++ (v$AFL_VERSION) -> $AFL_ROOT"

    if [[ -e "$AFL_ROOT/GNUmakefile" ]]; then
        echo "  already present, skipping fetch"
    elif [[ -e "$AFL_ROOT" ]]; then
        err "$AFL_ROOT exists but has no GNUmakefile - that is not an AFL++ tree."
        err "Point \$AFL_ROOT elsewhere, or remove it yourself."
        exit 1
    else
        run git clone --branch "v$AFL_VERSION" --depth 1 \
            https://github.com/AFLplusplus/AFLplusplus.git "$AFL_ROOT"
    fi

    # AFL++ build knobs, passed on the command line rather than exported, so
    # they cannot leak into anything else built in this shell.
    local -a afl_vars=(
        AFL_ROOT="$AFL_ROOT"
        PREFIX="$PREFIX"
        LLVM_CONFIG=llvm-config-16
        NO_PYTHON=1 NO_UTF=1 NO_NYX=1
        NO_CORESIGHT=1 NO_QEMU=1 NO_FRIDA=1 NO_UNICORN=1
    )

    log "overlaying AFL_patches/ and installing into $PREFIX"
    echo "  note: 'make link' FORCE-replaces the patched files inside $AFL_ROOT"
    echo "        with symlinks into $EGF_ROOT/AFL_patches (by design)."

    run mkdir -p "$PREFIX/bin"

    # The repo Makefile does audit -> symlink overlay -> source-only -> install.
    if [[ $DRY_RUN -eq 1 ]]; then
        # `make dry-run` is read-only, but it needs both trees to exist first.
        if [[ -d "$AFL_ROOT" ]]; then
            make -C "$EGF_ROOT" "${afl_vars[@]}" dry-run
        else
            echo "  ($AFL_ROOT not fetched yet - 'make dry-run' skipped)"
        fi
        run make -C "$EGF_ROOT" "${afl_vars[@]}" all
    else
        make -C "$EGF_ROOT" "${afl_vars[@]}" all
    fi
}

if [[ $DO_SVF -eq 1 ]]; then bootstrap_svf; fi
if [[ $DO_AFL -eq 1 ]]; then bootstrap_afl; fi

log "done"
if [[ $DRY_RUN -eq 0 ]]; then
    echo "  next: ./readycheck.sh"
fi
