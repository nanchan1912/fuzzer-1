#!/usr/bin/env bash
set -euo pipefail

EXPECTED_LLVM_MAJOR=16


# Ready Check Script for SVF Development Environment

PASS=0
FAIL=0

green()  { printf "\033[32m%s\033[0m\n" "$1"; }
red()    { printf "\033[31m%s\033[0m\n" "$1"; }
yellow() { printf "\033[33m%s\033[0m\n" "$1"; }

pass() {
    green "[PASS] $1"
    PASS=$((PASS + 1))
}

fail() {
    red "[FAIL] $1"
    FAIL=$((FAIL + 1))
}

check_cmd() {
    local cmd="$1"

    if command -v "$cmd" >/dev/null 2>&1; then
        pass "$cmd"
    else
        fail "$cmd"
    fi
}

check_file() {
    local path="$1"

    if [ -e "$path" ]; then
        pass "$path"
    else
        fail "$path"
    fi
}

check_python() {
    local mod="$1"

    if python3 -c "import $mod" >/dev/null 2>&1; then
        pass "python:$mod"
    else
        fail "python:$mod"
    fi
}

echo
yellow "===== Environment ====="

echo "CC=${CC:-<unset>}"
echo "CXX=${CXX:-<unset>}"
echo "SVF_DIR=${SVF_DIR:-<unset>}"
echo "LLVM_DIR=${LLVM_DIR:-<unset>}"
echo "Z3_DIR=${Z3_DIR:-<unset>}"

echo
yellow "===== Core Toolchain ====="

check_cmd clang-${EXPECTED_LLVM_MAJOR}
check_cmd clang++-${EXPECTED_LLVM_MAJOR}
check_cmd llvm-config
check_cmd opt
check_cmd llc
check_cmd llvm-link
check_cmd llvm-dis

echo
yellow "===== AFL++ ====="

check_cmd afl-fuzz
check_cmd afl-clang-fast
check_cmd afl-showmap

echo
yellow "===== AFL++ Overlay ====="

AFL_ROOT="${AFL_ROOT:-/workspaces/AFLplusplus}"
PATCH_ROOT="${PATCH_ROOT:-AFL_patches}"

if [ -d "$AFL_ROOT" ]; then
    pass "AFL_ROOT exists"
else
    fail "AFL_ROOT exists"
fi

if [ -d "$PATCH_ROOT" ]; then

    pass "PATCH_ROOT exists"

    LINK_COUNT=0

    while IFS= read -r f; do

        dst="$AFL_ROOT/$f"

        if [ -L "$dst" ]; then
            LINK_COUNT=$((LINK_COUNT + 1))
        fi

    done < <(
        cd "$PATCH_ROOT" && \
        find . -type f \
            ! -name '*.o' \
            ! -name '*.a' \
            ! -name '*.so' \
            ! -name '*.pyc' \
            ! -path '*/__pycache__/*' \
            | sed 's|^\./||'
    )

    echo "Detected overlay symlinks: $LINK_COUNT"

    if [ "$LINK_COUNT" -gt 0 ]; then
        pass "Patch overlay present"
    else
        fail "Patch overlay present"
    fi

else
    yellow "[INFO] PATCH_ROOT not present; skipping overlay validation"
fi

echo
yellow "===== AFL Instrumentation ====="

# Deliberately NOT named TMPDIR: assigning to the exported TMPDIR and then
# rm -rf'ing it leaves every later child process pointing at a deleted
# directory (e.g. Nix's cc-wrapper does `mktemp $TMPDIR/cc-params.XXXXXX`).
WORKDIR=$(mktemp -d)

cat > "$WORKDIR/test.c" <<'EOF'
int main(void) { return 0; }
EOF

if afl-clang-fast "$WORKDIR/test.c" -o "$WORKDIR/test" >/dev/null 2>&1; then
    pass "afl-clang-fast compile"
else
    fail "afl-clang-fast compile"
fi

rm -rf "$WORKDIR"

echo
yellow "===== AFL Binary Resolution ====="

for bin in afl-fuzz afl-showmap afl-clang-fast; do

    path=$(command -v "$bin" || true)

    if [ -n "$path" ]; then
        echo "$bin -> $path"
        pass "$bin resolved"
    else
        fail "$bin resolved"
    fi

done

echo
yellow "===== Build Tools ====="

check_cmd cmake
check_cmd make
check_cmd ninja
check_cmd gcc
check_cmd g++
check_cmd git
check_cmd gdb

echo
yellow "===== Analysis Tools ====="

check_cmd spatch
check_cmd dot
check_cmd gnuplot

echo
yellow "===== Python ====="

check_cmd python3
check_python graphviz

echo
yellow "===== LLVM Installation ====="

# Honour LLVM_DIR (Nix store prefix, custom builds); fall back to the
# Debian/devcontainer layout.
LLVM_PREFIX="${LLVM_DIR:-/usr/lib/llvm-${EXPECTED_LLVM_MAJOR}}"

check_file "${LLVM_PREFIX}/bin/clang"
check_file "${LLVM_PREFIX}/bin/opt"
check_file "${LLVM_PREFIX}/bin/llvm-config"
check_file "${LLVM_PREFIX}/include"
check_file "${LLVM_PREFIX}/lib"

echo
yellow "===== LLVM Version ====="

if command -v llvm-config-${EXPECTED_LLVM_MAJOR} >/dev/null 2>&1; then

    ACTUAL_LLVM_MAJOR=$(
        llvm-config-${EXPECTED_LLVM_MAJOR} --version \
        | cut -d. -f1
    )

    if [ "$ACTUAL_LLVM_MAJOR" = "$EXPECTED_LLVM_MAJOR" ]; then
        pass "LLVM major version ${EXPECTED_LLVM_MAJOR}"
    else
        fail "LLVM major version ${EXPECTED_LLVM_MAJOR}"
    fi

else
    fail "llvm-config-${EXPECTED_LLVM_MAJOR}"
fi

if command -v clang-${EXPECTED_LLVM_MAJOR} >/dev/null 2>&1; then

    ACTUAL_CLANG_MAJOR=$(
        clang-${EXPECTED_LLVM_MAJOR} --version \
        | grep -oE '[0-9]+' \
        | head -n1
    )

    if [ "$ACTUAL_CLANG_MAJOR" = "$EXPECTED_LLVM_MAJOR" ]; then
        pass "Clang major version ${EXPECTED_LLVM_MAJOR}"
    else
        fail "Clang major version ${EXPECTED_LLVM_MAJOR}"
    fi

else
    fail "clang-${EXPECTED_LLVM_MAJOR}"
fi

echo
yellow "===== Z3 ====="

# Honour Z3_DIR (Nix store prefix); the devcontainer sets Z3_DIR=/usr, so the
# container behaviour is unchanged.
Z3_PREFIX="${Z3_DIR:-/usr}"

check_file "${Z3_PREFIX}/include/z3.h"

if find "${Z3_PREFIX}/lib" /lib /usr/lib -name "libz3.so*" 2>/dev/null | grep -q .; then
    pass "libz3 present"
else
    fail "libz3 present"
fi

echo
yellow "===== SVF ====="

check_file "${SVF_DIR:-/workspaces/SVF}"
check_file "${SVF_DIR:-/workspaces/SVF}/build"

if [ -d "${SVF_DIR:-/workspaces/SVF}/build/bin" ]; then

    find "${SVF_DIR:-/workspaces/SVF}/build/bin" \
        -maxdepth 1 \
        -type f \
        -executable \
        2>/dev/null \
        | sort

    echo

    for bin in \
        llvm2svf \
        wpa \
        svf-ex \
        ae \
        saber \
        mta \
        cfl \
        dvf
    do
        if command -v "$bin" >/dev/null 2>&1; then
            pass "$bin"
        else
            fail "$bin"
        fi
    done

fi

echo
yellow "===== Functional Checks ====="

if command -v llvm2svf >/dev/null 2>&1; then
    llvm2svf --help >/dev/null 2>&1 \
        && pass "llvm2svf executable works" \
        || fail "llvm2svf executable works"
fi

if command -v wpa >/dev/null 2>&1; then
    wpa --help >/dev/null 2>&1 \
        && pass "wpa executable works" \
        || fail "wpa executable works"
fi

if command -v svf-ex >/dev/null 2>&1; then
    svf-ex --help >/dev/null 2>&1 \
        && pass "svf-ex executable works" \
        || fail "svf-ex executable works"
fi

echo
yellow "===== Shared Library Resolution ====="

if command -v wpa >/dev/null 2>&1; then

    if ldd "$(command -v wpa)" | grep -q "not found"; then
        fail "wpa shared libraries"
    else
        pass "wpa shared libraries"
    fi

fi

echo
yellow "===== Summary ====="

echo "PASS: $PASS"
echo "FAIL: $FAIL"

if [ "$FAIL" -eq 0 ]; then
    green "Environment looks healthy."
    exit 0
else
    red "Environment has missing components."
    exit 1
fi