#
# Nix devShell that reproduces .devcontainer/Dockerfile.
#
# Differences from the container, on purpose:
#   * nothing lives under /workspaces; the mutable trees (AFL++, SVF, install
#     prefix) live in the *parent* directory of this repo, so they persist
#     across shells and across `nix store gc`.
#   * LLVM/clang come from the Nix store, but versioned aliases (clang-16,
#     llvm-config-16, opt-16, ...) are synthesised because every script in this
#     repo hard-codes the Debian-style `-16` suffix.
#
{ pkgs ? import <nixpkgs> { } }:

let
  inherit (pkgs) lib;

  llvmPkgs = pkgs.llvmPackages_16;

  # A Debian-like /usr/lib/llvm-16 prefix: bin/, lib/, include/, lib/cmake/llvm.
  # readycheck.sh and run_all_analysis_compile.sh both expect LLVM_DIR to be a
  # real directory shaped like this.
  llvmPrefix = pkgs.symlinkJoin {
    name = "llvm-16-prefix";
    paths = [
      llvmPkgs.llvm.out
      llvmPkgs.llvm.dev
      llvmPkgs.clang-unwrapped
      llvmPkgs.clang-unwrapped.lib
      llvmPkgs.lld
      llvmPkgs.compiler-rt
    ];
    # clang-unwrapped contributes bin/clang{,++,-16}, which cannot find glibc or
    # its own resource-dir headers ("fatal error: 'stddef.h' file not found").
    # CMake reaches these via CMAKE_PREFIX_PATH, and SVF builds extapi.bc with
    # ${LLVM_TOOLS_BINARY_DIR}/clang == this prefix. Point them at the wrappers.
    postBuild = ''
      for n in clang clang++ clang-16 clang++-16 cc c++; do
        rm -f "$out/bin/$n"
      done
      ln -s ${llvmPkgs.clang}/bin/clang   "$out/bin/clang"
      ln -s ${llvmPkgs.clang}/bin/clang++ "$out/bin/clang++"
      ln -s ${llvmPkgs.clang}/bin/clang   "$out/bin/clang-16"
      ln -s ${llvmPkgs.clang}/bin/clang++ "$out/bin/clang++-16"
    '';
  };

  # `clang-16`, `clang++-16`, `llvm-config-16`, `opt-16`, ... on PATH.
  # clang/clang++ must be the *wrapped* ones so libc/libstdc++ headers resolve.
  llvmCompat = pkgs.runCommand "llvm-16-compat-bin" { } ''
    mkdir -p "$out/bin"

    ln -s ${llvmPkgs.clang}/bin/clang   "$out/bin/clang-16"
    ln -s ${llvmPkgs.clang}/bin/clang++ "$out/bin/clang++-16"

    for dir in ${llvmPkgs.llvm.out}/bin ${llvmPkgs.llvm.dev}/bin \
               ${llvmPkgs.clang-unwrapped}/bin ${llvmPkgs.lld}/bin \
               ${llvmPkgs.clang-tools}/bin; do
      [ -d "$dir" ] || continue
      for tool in "$dir"/*; do
        name="$(basename "$tool")"
        case "$name" in
          clang|clang++) continue ;;   # keep the wrapped ones above
          *-16) continue ;;            # already versioned; no clang-16-16
        esac
        [ -e "$out/bin/$name-16" ] || ln -s "$tool" "$out/bin/$name-16"
      done
    done
  '';

  # SVF's CMake wants a prefix with include/ and lib/ under $Z3_DIR.
  z3Prefix = pkgs.symlinkJoin {
    name = "z3-prefix";
    paths = [ pkgs.z3.out pkgs.z3.dev pkgs.z3.lib ];
  };

  pythonEnv = pkgs.python3.withPackages (ps: with ps; [
    graphviz
    setuptools
    pip
  ]);

in
pkgs.mkShell {
  name = "egf-dev";

  # -O0 fuzzing targets + _FORTIFY_SOURCE do not mix; AFL++ dislikes the rest.
  hardeningDisable = [ "all" ];

  nativeBuildInputs = with pkgs; [
    llvmCompat
    llvmPkgs.clang # unsuffixed clang / clang++ as well
    llvmPkgs.bintools
    llvmPkgs.clang-tools

    cmake
    ninja
    meson
    gnumake
    pkg-config
    bc
    which
    file
    perl
    gdb
    git
    curl
    wget
    unzip
    cacert

    coccinelle # spatch
    graphviz # dot
    gnuplot
    pythonEnv
  ];

  buildInputs = with pkgs; [
    llvmPkgs.llvm
    llvmPkgs.compiler-rt
    z3
    boost
    capstone
    cjson # tests/sanity json_fuzz links -lcjson
    glib
    gmp
    libaio
    libunwind
    libxml2 # LLVM's cmake config looks for it ("Could NOT find LibXml2")
    ncurses
    ncurses5 # libtinfo5/libncurses5 ABI compat, as in the Dockerfile
    readline
    zlib
    zstd
  ];

  # Anything that must not be a store path is resolved in the shellHook so the
  # locations follow wherever the repo is checked out.
  LLVM_DIR = "${llvmPrefix}";
  Z3_DIR = "${z3Prefix}";
  LLVM_MAJOR = "16";

  # NOTE: the AFL++ build knobs (NO_PYTHON, NO_NYX, LLVM_CONFIG, ...) are
  # deliberately *not* exported here. As global env vars they would leak into
  # every unrelated build run in this shell; nix/bootstrap.sh passes them on the
  # `make` command line instead, where they cannot escape.

  shellHook = ''
    export EGF_ROOT="''${EGF_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
    # Mutable, persistent trees live one directory *above* the repo.
    export EGF_EXT="''${EGF_EXT:-$(dirname "$EGF_ROOT")}"

    export AFL_ROOT="''${AFL_ROOT:-$EGF_EXT/AFLplusplus}"
    export SVF_DIR="''${SVF_DIR:-$EGF_EXT/SVF}"
    export PREFIX="''${PREFIX:-$EGF_EXT/.egf-prefix}"

    export CC=clang-16
    export CXX=clang++-16
    export CMAKE_C_COMPILER=clang-16
    export CMAKE_CXX_COMPILER=clang++-16

    export PATH="$PREFIX/bin:$SVF_DIR/build/bin:$PATH"
    # ':' suffix matters: an empty element in LD_LIBRARY_PATH means "cwd" to the
    # loader, so only append the old value when it is actually set.
    export LD_LIBRARY_PATH="$SVF_DIR/build/svf:$SVF_DIR/build/svf-llvm''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    export CMAKE_PREFIX_PATH="$LLVM_DIR:$Z3_DIR''${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}"
    export SSL_CERT_FILE="''${SSL_CERT_FILE:-${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt}"

    # Entering the shell is read-only on purpose: nothing is created outside the
    # store here. $PREFIX is created by nix/bootstrap.sh when it actually installs.

    cat <<EOF
[egf-dev shell]
  EGF_ROOT : $EGF_ROOT
  EGF_EXT  : $EGF_EXT      (AFL++ / SVF / install prefix live here)
  AFL_ROOT : $AFL_ROOT $([ -d "$AFL_ROOT" ] && echo '(present)' || echo '(MISSING - run: bootstrap-egf)')
  SVF_DIR  : $SVF_DIR $([ -d "$SVF_DIR/build" ] && echo '(built)' || echo '(MISSING - run: bootstrap-egf)')
  PREFIX   : $PREFIX
  LLVM_DIR : $LLVM_DIR
  Z3_DIR   : $Z3_DIR

  bootstrap-egf --dry-run   # show what would be fetched/built
  bootstrap-egf             # fetch + build SVF and patched AFL++
  ./readycheck.sh           # verify
EOF

    # Not `export -f`: keep the helper in this shell only, out of child processes.
    bootstrap-egf() { "$EGF_ROOT/nix/bootstrap.sh" "$@"; }
  '';
}
