# Nix environment (devcontainer parity, without Docker)

Same toolchain as `.devcontainer/`, provided by Nix instead of an Ubuntu image.
The **immutable** half (LLVM 16, clang, cmake, ninja, coccinelle, graphviz,
gnuplot, boost, z3, cjson, ncurses5 compat, …) comes from the Nix store. The
**mutable** half (AFL++ source tree, SVF checkout + build, install prefix) lives
one directory *above* this repo so it survives shell exits, rebuilds and
`nix store gc`.

```
/home/nitheesh/Research/WMM/          <- $EGF_EXT
├── EGF-dev/                          <- $EGF_ROOT (this repo)
├── AFLplusplus/                      <- $AFL_ROOT   (cloned, patch-overlaid)
├── SVF/                              <- $SVF_DIR    (cloned, built with ninja)
└── .egf-prefix/                      <- $PREFIX     (afl-* install target)
    └── bin/
```

## One-time setup

Flakes are still gated behind experimental features on this machine:

```bash
mkdir -p ~/.config/nix
printf 'experimental-features = nix-command flakes\n' >> ~/.config/nix/nix.conf
```

Nix flakes only see **git-tracked** files, so the new files must be in the index
at least as intent-to-add:

```bash
git add -N flake.nix nix/shell.nix nix/bootstrap.sh .envrc
```

## Daily use

```bash
cd /home/nitheesh/Research/WMM/EGF-dev
nix develop                  # enter the shell (prints the resolved paths)

bootstrap-egf --dry-run      # show what would be fetched/built
bootstrap-egf                # clone+build SVF, clone+patch+build AFL++ into $PREFIX
./readycheck.sh              # verify
```

Optional, auto-enter via direnv:

```bash
nix profile install nixpkgs#direnv nixpkgs#nix-direnv
direnv allow                 # .envrc already contains `use flake`
```

Add to shell
```
echo 'eval "$(direnv hook bash)"' >> ~/.bashrc
```

## What the shell sets

| Variable | Value |
| --- | --- |
| `EGF_ROOT` | repo root (`git rev-parse --show-toplevel`) |
| `EGF_EXT` | parent of the repo — override to relocate all mutable state |
| `AFL_ROOT` | `$EGF_EXT/AFLplusplus` (the repo `Makefile` default was `/workspaces/AFLplusplus`) |
| `SVF_DIR` | `$EGF_EXT/SVF` |
| `PREFIX` | `$EGF_EXT/.egf-prefix`, prepended to `PATH` — no `sudo` needed for `make install` |
| `LLVM_DIR` | a store-side `/usr/lib/llvm-16`-shaped prefix (`bin/ lib/ include/ lib/cmake/llvm`) |
| `Z3_DIR` | store-side z3 prefix (`include/ lib/`) |
| `CC` / `CXX` | `clang-16` / `clang++-16` |

The AFL++ knobs (`LLVM_CONFIG=llvm-config-16`, `NO_PYTHON`, `NO_UTF`, `NO_NYX`,
`NO_CORESIGHT`, `NO_QEMU`, `NO_FRIDA`, `NO_UNICORN`) are **not** exported into
the shell — as globals they would leak into every unrelated build you run here.
`nix/bootstrap.sh` passes them on the `make` command line instead. If you invoke
`make` by hand, use `bootstrap-egf --afl-only` so you get the same flags.

## Side-effect contract

* **Entering the shell writes nothing** outside the Nix store — no `mkdir`, no
  clone, no config file. It only sets environment variables.
* **`bootstrap-egf --dry-run` writes nothing.** Verified: a sandbox tree is
  byte-identical before and after, including the read-only `make dry-run` pass.
* **`bootstrap-egf` writes to exactly three places**, all under `$EGF_EXT`:
  `$AFL_ROOT`, `$SVF_DIR`, `$PREFIX`. It never writes to `$HOME`, `/usr`,
  `/workspaces`, or system paths, and never needs `sudo`.
* It **refuses** to clone into or build on top of a pre-existing `$SVF_DIR`
  that is not a git checkout, or an `$AFL_ROOT` with no `GNUmakefile`, rather
  than clobbering whatever is there.
* The one intentionally destructive step is the repo's own `make link`, which
  FORCE-replaces the patched files inside `$AFL_ROOT` with symlinks into
  `AFL_patches/`. Bootstrap prints a notice before doing it. It only ever
  touches the AFL++ clone it manages.
* `.envrc` is inert until you run `direnv allow`.
* `~/.config/nix/nix.conf` is **not** modified by anything here — the flakes
  line above is a manual step.

Every script in this repo calls `clang-16`, `clang++-16`, `llvm-config-16`,
`opt-16`, … Nix ships unsuffixed names, so `nix/shell.nix` builds a small
symlink farm (`llvm-16-compat-bin`) that adds the `-16` aliases; `clang-16` and
`clang++-16` point at the *wrapped* compilers so libc/libstdc++ headers resolve.

`$LLVM_DIR/bin/clang{,++,-16,++-16}` are overridden to the wrapped compilers for
the same reason. `clang-unwrapped` contributes the prefix's headers, libs and
cmake files, but its `clang` binary knows no glibc include path — SVF builds
`extapi.bc` with `${LLVM_TOOLS_BINARY_DIR}/clang` and fails with
`fatal error: 'stddef.h' file not found` if it gets the unwrapped one.
`bootstrap.sh` additionally passes `CMAKE_C_COMPILER` as an absolute path, since
a bare `clang-16` gets resolved through `CMAKE_PREFIX_PATH`.

If you change the toolchain, `$SVF_DIR/build/CMakeCache.txt` still pins the old
compiler paths — re-run with `bootstrap-egf --reconfigure`.

Override anything before entering the shell, e.g. reuse an existing checkout:

```bash
SVF_DIR=/somewhere/else/SVF nix develop
```

## Known gaps vs. the devcontainer

* `readycheck.sh` needed two fixes to run outside the container (both applied):
  `LLVM_PREFIX` now honours `$LLVM_DIR` instead of hard-coding
  `/usr/lib/llvm-16`, and its scratch dir was renamed `TMPDIR` -> `WORKDIR`.
  The latter was a latent bug: it assigned to the *exported* `TMPDIR` and then
  `rm -rf`'d it, so every later child process inherited a deleted temp dir.
  Invisible with Debian's clang, fatal with Nix's cc-wrapper, which does
  `mktemp $TMPDIR/cc-params.XXXXXX` — it aborted the script under `set -e`
  before the SVF section ran.
* `result_pct.sh` / `result_pctwm.sh` symlink `/workspaces/PCTversion` and
  `/workspaces/PCTWMversion`, which have no local equivalent yet.
* AFL++'s `gcc_plugin` (the container's `gcc-13-plugin-dev`) is not provided.
  The AFL++ makefile invokes it with `-$(MAKE)`, so the failure is ignored and
  `afl-clang-fast` still builds.
* `run_profiling.sh` needs `valgrind`, which the Dockerfile did not install
  either — add `pkgs.valgrind` to `nix/shell.nix` if you want it.
