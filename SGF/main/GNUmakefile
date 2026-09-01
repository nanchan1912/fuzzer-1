#
# american fuzzy lop++ - makefile
# -----------------------------
#
# Originally written by Michal Zalewski
#
# Copyright 2013, 2014, 2015, 2016, 2017 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   https://www.apache.org/licenses/LICENSE-2.0
#

# For Heiko:
#TEST_MMAP=1
# the hash character is treated differently in different make versions
# so use a variable for '#'
HASH=\#

PREFIX      ?= /usr/local
BIN_PATH     = $(PREFIX)/bin
HELPER_PATH  = $(PREFIX)/lib/sgf
DOC_PATH     = $(PREFIX)/share/doc/sgf
MISC_PATH    = $(PREFIX)/share/sgf
MAN_PATH     = $(PREFIX)/share/man/man8
INCLUDE_PATH = $(PREFIX)/include/sgf

PROGNAME    = afl
VERSION     = $(shell grep '^$(HASH)define VERSION ' ../config.h | cut -d '"' -f2)

PROGS       = sgf-fuzz sgf-showmap sgf-tmin sgf-gotcpu sgf-analyze
ASAN_OPTIONS=detect_leaks=0

SYS = $(shell uname -s)
ARCH = $(shell uname -m)

$(info [*] Compiling SGF for OS $(SYS) on ARCH $(ARCH))

ifdef NO_UTF
  override CFLAGS_OPT += -DFANCY_BOXES_NO_UTF
endif

# ASAN: AddressSanitizer
ifdef ASAN_BUILD
  $(info Compiling ASAN version of binaries)
  override CFLAGS += $(ASAN_CFLAGS)
  override LDFLAGS += $(ASAN_LDFLAGS)
endif
# UBSAN: UndefinedBehaviorSanitizer
ifdef UBSAN_BUILD
  $(info Compiling UBSAN version of binaries)
  override CFLAGS += -fsanitize=undefined -fno-omit-frame-pointer
  override LDFLAGS += -fsanitize=undefined
endif
# MSAN: MemorySanitizer
ifdef MSAN_BUILD
  $(info Compiling MSAN version of binaries)
  CC := clang
  override CFLAGS += -fsanitize=memory -fno-omit-frame-pointer
  override LDFLAGS += -fsanitize=memory
endif
ifdef NO_SPLICING
  $(info The NO_SPLICING parameter is deprecated)
endif


ifdef CODE_COVERAGE
  override CFLAGS += -D__AFL_CODE_COVERAGE=1
endif

IS_IOS:=$(findstring ios, $(shell $(CC) --version 2>/dev/null))
ifdef IS_IOS
  override CFLAGS += -DTARGET_OS_IPHONE -DTARGET_OS_IOS -isysroot $(IOS_SDK_PATH)
endif

ifeq "$(findstring android, $(shell $(CC) --version 2>/dev/null))" ""
ifndef ASAN_BUILD
 ifeq "$(shell echo 'int main() {return 0; }' | $(CC) $(CFLAGS) -Werror -x c - -flto=full -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	CFLAGS_FLTO ?= -flto=full
 else
  ifeq "$(shell echo 'int main() {return 0; }' | $(CC) $(CFLAGS) -Werror -x c - -flto=thin -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	CFLAGS_FLTO ?= -flto=thin
  else
   ifeq "$(shell echo 'int main() {return 0; }' | $(CC) $(CFLAGS) -Werror -x c - -flto -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	CFLAGS_FLTO ?= -flto
   endif
  endif
 endif
endif
endif

ifdef PERFORMANCE
  SPECIAL_PERFORMANCE := -D_AFL_SPECIAL_PERFORMANCE
  ifeq "$(SYS)" "Linux"
    ifeq "$(shell grep avx2 /proc/cpuinfo)" ""
    else
	SPECIAL_PERFORMANCE += -mavx2 -D_HAVE_AVX2
    endif
  endif
  ifeq "$(shell echo 'int main() {return 0; }' | $(CC) $(CFLAGS) -Werror -x c - -march=native -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	HAVE_MARCHNATIVE = 1
	SPECIAL_PERFORMANCE += -march=native
  endif
  $(info SPECIAL_PERFORMANCE=$(SPECIAL_PERFORMANCE))
else
  SPECIAL_PERFORMANCE :=
endif

ifndef IS_IOS
  ifneq "$(SYS)" "Darwin"
   #ifeq "$(HAVE_MARCHNATIVE)" "1"
   #  SPECIAL_PERFORMANCE += -march=native
   #endif
   #ifndef DEBUG
   #  override CFLAGS_OPT += -D_FORTIFY_SOURCE=1
   #endif
  else
    # On some odd MacOS system configurations, the Xcode sdk path is not set correctly
    SDK_LD = -L$(shell xcrun --show-sdk-path)/usr/lib
    override LDFLAGS += $(SDK_LD)
  endif
endif

COMPILER_TYPE=$(shell $(CC) --version|grep "Free Software Foundation")
ifneq "$(COMPILER_TYPE)" ""
  #$(info gcc is being used)
  override CFLAGS_OPT += -Wno-format-truncation
endif

ifeq "$(SYS)" "SunOS"
  override LDFLAGS = -lkstat -lrt -lsocket -lnsl
endif

ifdef STATIC
  $(info Compiling static version of binaries, disabling python though)
  # Disable python for static compilation to simplify things
  PYTHON_OK = 0
  PYFLAGS=
  PYTHON_INCLUDE = /

  override CFLAGS_OPT += -static
  override LDFLAGS += -lm -lpthread -lz -lutil
endif

ifdef PROFILING
  $(info Compiling with profiling information, for analysis: gprof ./sgf-fuzz gmon.out > prof.txt)
  override CFLAGS_OPT += -pg -DPROFILING=1
  override LDFLAGS += -pg
endif

ifdef INTROSPECTION
  $(info Compiling with introspection documentation)
  override CFLAGS_OPT += -DINTROSPECTION=1
endif

ifneq "$(ARCH)" "x86_64"
 ifneq "$(patsubst i%86,i386,$(ARCH))" "i386"
  ifneq "$(ARCH)" "amd64"
   ifneq "$(ARCH)" "i86pc"
	AFL_NO_X86=1
   endif
  endif
 endif
endif

ifdef DEBUG
  $(info Compiling DEBUG version of binaries)
  override CFLAGS += -ggdb3 -O0 -Wall -Wextra -Werror $(CFLAGS_OPT)
else
  CFLAGS ?= -O2 $(CFLAGS_OPT) # -funroll-loops is slower on modern compilers
endif

override CFLAGS += -g -Wno-pointer-sign -Wno-variadic-macros -Wall -Wextra -Wno-pointer-arith \
			-fPIC -I include/ -DSGF_PATH=\"$(HELPER_PATH)\"  \
			-DBIN_PATH=\"$(BIN_PATH)\" -DDOC_PATH=\"$(DOC_PATH)\"
# -fstack-protector

ifeq "$(SYS)" "FreeBSD"
  override CFLAGS  += -I /usr/local/include/
  override LDFLAGS += -L /usr/local/lib/
endif

ifeq "$(SYS)" "DragonFly"
  override CFLAGS  += -I /usr/local/include/
  override LDFLAGS += -L /usr/local/lib/
endif

ifeq "$(SYS)" "OpenBSD"
  override CFLAGS  += -I /usr/local/include/ -mno-retpoline
  override LDFLAGS += -Wl,-z,notext -L /usr/local/lib/
endif

ifeq "$(SYS)" "NetBSD"
  override CFLAGS  += -I /usr/pkg/include/
  override LDFLAGS += -L /usr/pkg/lib/
endif

ifeq "$(SYS)" "Haiku"
  SHMAT_OK=0
  override CFLAGS  += -DUSEMMAP=1 -Wno-error=format
  override LDFLAGS += -Wno-deprecated-declarations -lgnu -lnetwork
  #SPECIAL_PERFORMANCE += -DUSEMMAP=1
endif

AFL_FUZZ_FILES = $(filter-out src/sgf-fuzz-frameshift.c,$(wildcard src/sgf-fuzz*.c))

ifneq "$(shell command -v python3m 2>/dev/null)" ""
  ifneq "$(shell command -v python3m-config 2>/dev/null)" ""
    PYTHON_INCLUDE  := $(shell python3m-config --includes)
    PYTHON_VERSION  := $(strip $(shell python3m --version 2>&1))
    # Starting with python3.8, we need to pass the `embed` flag. Earlier versions didn't know this flag.
    ifeq "$(shell python3m-config --embed --libs 2>/dev/null | grep -q lpython && echo 1 )" "1"
      PYTHON_LIB      := $(shell python3m-config --libs --embed --ldflags)
    else
      PYTHON_LIB      := $(shell python3m-config --ldflags)
    endif
  endif
endif

ifeq "$(PYTHON_INCLUDE)" ""
  ifneq "$(shell command -v python3 2>/dev/null)" ""
    ifneq "$(shell command -v python3-config 2>/dev/null)" ""
      PYTHON_INCLUDE  := $(shell python3-config --includes)
      PYTHON_VERSION  := $(strip $(shell python3 --version 2>&1))
      # Starting with python3.8, we need to pass the `embed` flag. Earlier versions didn't know this flag.
      ifeq "$(shell python3-config --embed --libs 2>/dev/null | grep -q lpython && echo 1 )" "1"
        PYTHON_LIB      := $(shell python3-config --libs --embed --ldflags)
      else
        PYTHON_LIB      := $(shell python3-config --ldflags)
      endif
    endif
  endif
endif

ifeq "$(PYTHON_INCLUDE)" ""
  ifneq "$(shell command -v python 2>/dev/null)" ""
    ifneq "$(shell command -v python-config 2>/dev/null)" ""
      PYTHON_INCLUDE  := $(shell python-config --includes)
      PYTHON_LIB      := $(shell python-config --ldflags)
      PYTHON_VERSION  := $(strip $(shell python --version 2>&1))
    endif
  endif
endif

# Old Ubuntu and others dont have python/python3-config so we hardcode 3.7
ifeq "$(PYTHON_INCLUDE)" ""
  ifneq "$(shell command -v python3.7 2>/dev/null)" ""
    ifneq "$(shell command -v python3.7-config 2>/dev/null)" ""
      PYTHON_INCLUDE  := $(shell python3.7-config --includes)
      PYTHON_LIB      := $(shell python3.7-config --ldflags)
      PYTHON_VERSION  := $(strip $(shell python3.7 --version 2>&1))
    endif
  endif
endif

ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "+%Y-%m-%d" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "+%Y-%m-%d" 2>/dev/null || date -u "+%Y-%m-%d")
else
    BUILD_DATE ?= $(shell date "+%Y-%m-%d")
endif

ifneq "$(filter Linux GNU%,$(SYS))" ""
  override LDFLAGS += -ldl -lrt -lm
endif

ifneq "$(findstring FreeBSD, $(SYS))" ""
  override CFLAGS  += -pthread
  override LDFLAGS += -lpthread -lm
endif

ifneq "$(findstring NetBSD, $(SYS))" ""
  override CFLAGS  += -pthread
  override LDFLAGS += -lpthread -lm
endif

ifneq "$(findstring OpenBSD, $(SYS))" ""
  override CFLAGS  += -pthread
  override LDFLAGS += -lpthread -lm
endif

COMM_HDR    = include/alloc-inl.h include/config.h include/debug.h include/types.h include/sgf-fuzz.h include/hash.h include/sharedmem.h include/forkserver.h include/common.h include/list.h

ifeq "$(shell echo '$(HASH)include <Python.h>@int main() {return 0; }' | tr @ '\n' | $(CC) $(CFLAGS) -x c - -o .test $(PYTHON_INCLUDE) $(LDFLAGS) $(PYTHON_LIB) 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	PYTHON_OK=1
	PYFLAGS=-DUSE_PYTHON $(PYTHON_INCLUDE) $(LDFLAGS) $(PYTHON_LIB) -DPYTHON_VERSION="\"$(PYTHON_VERSION)\""
else
	PYTHON_OK=0
	PYFLAGS=
endif

ifdef NO_PYTHON
	PYTHON_OK=0
	PYFLAGS=
endif

IN_REPO=0
ifeq "$(shell command -v git >/dev/null && git status >/dev/null 2>&1 && echo 1 || echo 0)" "1"
  IN_REPO=1
endif
ifeq "$(shell command -v svn >/dev/null && svn proplist . 2>/dev/null && echo 1 || echo 0)" "1"
  IN_REPO=1
endif

ifeq "$(shell echo 'int main() { return 0;}' | $(CC) $(CFLAGS) -fsanitize=address -x c - -o .test2 2>/dev/null && echo 1 || echo 0 ; rm -f .test2 )" "1"
	ASAN_CFLAGS=-fsanitize=address -fstack-protector-all -fno-omit-frame-pointer -DASAN_BUILD -fno-lto
	ASAN_LDFLAGS=-fsanitize=address -fstack-protector-all -fno-omit-frame-pointer -fno-lto
endif

ifeq "$(shell echo '$(HASH)include <sys/ipc.h>@$(HASH)include <sys/shm.h>@int main() { int _id = shmget(IPC_PRIVATE, 65536, IPC_CREAT | IPC_EXCL | 0600); shmctl(_id, IPC_RMID, 0); return 0;}' | tr @ '\n' | $(CC) $(CFLAGS) -x c - -o .test2 2>/dev/null && echo 1 || echo 0 ; rm -f .test2 )" "1"
	SHMAT_OK=1
else
	SHMAT_OK=0
	override CFLAGS+=-DUSEMMAP=1
	LDFLAGS += -Wno-deprecated-declarations
endif

ifdef TEST_MMAP
	SHMAT_OK=0
	override CFLAGS += -DUSEMMAP=1
	LDFLAGS += -Wno-deprecated-declarations
endif

ifeq "$(ARCH)" "aarch64"
  ifdef NO_UNICORN_ARM64
	NO_UNICORN=1
  endif
endif

.PHONY: all
.PHONY: help
help:
	@echo "HELP --- the following make targets exist:"
	@echo "=========================================="
	@echo "sgf-fuzz: builds the main SGF fuzzer binary (this is what run.sh uses)"
	@echo "sgf-showmap: displays coverage bitmap for a given input"
	@echo "sgf-tmin: minimizes a testcase"
	@echo "sgf-analyze: analyzes byte-level dependencies in a testcase"
	@echo "sgf-gotcpu: shows which CPU cores are idle"
	@echo "clean: cleans everything compiled"
	@echo "help: shows these build options :-)"
	@echo "=========================================="
	@echo "Recommended: \"make sgf-fuzz\", then run via ./run.sh"
	@echo
	@echo Known build environment options:
	@echo "=========================================="
	@echo "PERFORMANCE - compile with performance options that make the binary not transferable to other systems. Recommended!"
	@echo STATIC - compile statically
	@echo "CODE_COVERAGE - compile the target for code coverage"
	@echo ASAN_BUILD - compiles with memory sanitizer for debug purposes
	@echo UBSAN_BUILD - compiles with undefined behaviour sanitizer for debug purposes
	@echo DEBUG - no optimization, -ggdb3, all warnings and -Werror
	@echo PROFILING - compile sgf-fuzz with profiling information
	@echo INTROSPECTION - compile sgf-fuzz with mutation introspection
	@echo NO_PYTHON - disable python support
	@echo "NO_UTF - do not use UTF-8 for line rendering in status screen"
	@echo AFL_NO_X86 - if compiling on non-intel/amd platforms
	@echo "=========================================="

.PHONY: test_x86
ifndef AFL_NO_X86
test_x86:
	@echo "[*] Checking for the default compiler cc..."
	@type $(CC) >/dev/null || ( echo; echo "Oops, looks like there is no compiler '"$(CC)"' in your path."; echo; echo "Don't panic! You can restart with '"$(_)" CC=<yourCcompiler>'."; echo; exit 1 )
	@echo "[*] Testing the PATH environment variable..."
	@test "$${PATH}" != "$${PATH#.:}" && { echo "Please remove current directory '.' from PATH to avoid recursion of 'as', thanks!"; echo; exit 1; } || :
	@echo "[*] Checking for the ability to compile x86 code..."
	@echo 'int main() { __asm__("xorb %al, %al"); }' | $(CC) $(CFLAGS) $(LDFLAGS) -w -x c - -o .test1 || ( echo; echo "Oops, looks like your compiler can't generate x86 code."; echo; echo "Don't panic! You can use the LLVM or QEMU mode, but see docs/INSTALL first."; echo "(To ignore this error, set AFL_NO_X86=1 and try again.)"; echo; exit 1 )
	@rm -f .test1
else
test_x86:
	@echo "[!] Note: skipping x86 compilation checks (AFL_NO_X86 set)."
endif

.PHONY: test_shm
ifeq "$(SHMAT_OK)" "1"
test_shm:
	@echo "[+] shmat seems to be working."
	@rm -f .test2
else
test_shm:
	@echo "[-] shmat seems not to be working, switching to mmap implementation"
endif

ifeq "$(shell echo '$(HASH)include <zlib.h>@int main() {return 0; }' | tr @ '\n' | $(CC) $(CFLAGS) -Werror -x c - -lz -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
  override SPECIAL_PERFORMANCE += -DHAVE_ZLIB
  override LDFLAGS += -lz
  $(info [+] ZLIB detected)
else
  $(info [!] Warning: no ZLIB detected)
endif

.PHONY: test_python
ifeq "$(PYTHON_OK)" "1"
test_python:
	@rm -f .test 2> /dev/null
	@echo "[+] $(PYTHON_VERSION) support seems to be working."
else
test_python:
	@echo "[-] You seem to need to install the package python3-dev or python-dev (and perhaps python[3]-apt), but it is optional so we continue"
endif

.PHONY: ready
ready:
	@echo "[+] Everything seems to be working, ready to compile. ($(shell $(CC) --version 2>&1|head -n 1))"

src/sgf-performance.o: $(COMM_HDR) src/sgf-performance.c
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) $(CFLAGS_OPT) $(SPECIAL_PERFORMANCE) -Iinclude -c src/sgf-performance.c -o src/sgf-performance.o

src/sgf-common.o: $(COMM_HDR) src/sgf-common.c include/envs.h
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) $(SPECIAL_PERFORMANCE) -c src/sgf-common.c -o src/sgf-common.o

src/sgf-forkserver.o: $(COMM_HDR) src/sgf-forkserver.c 
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) $(SPECIAL_PERFORMANCE) -c src/sgf-forkserver.c -o src/sgf-forkserver.o

src/sgf-sharedmem.o: $(COMM_HDR) src/sgf-sharedmem.c include/android-ashmem.h include/cmplog.h
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) $(SPECIAL_PERFORMANCE) -c src/sgf-sharedmem.c -o src/sgf-sharedmem.o


# --- Compile all C sources into .o ---
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# --- Compile all C++ sources into .o ---
# %.o: %.cpp
# 	$(CXX) $(CXXFLAGS) -c $< -o $@

# adding the include path for JOSN header
CXXFLAGS += -Iinclude

src/retgraph_shm.o: src/retgraph_shm.cpp \
    include/retgraph_shm.h
	$(CXX) $(CXXFLAGS) -c src/retgraph_shm.cpp -o $@


src/shm_next_events.o: src/shm_next_events.cpp \
    include/shm_next_events.h
	$(CXX) $(CXXFLAGS) -c src/shm_next_events.cpp -o $@

src/skeleton_graph_mutator.o: src/skeleton_graph_mutator.cpp \
    include/skeleton_graph_mutator_wrapper.h \
    include/skeleton_graph_mutator.hpp \
    include/json.hpp
	$(CXX) $(CXXFLAGS) -c src/skeleton_graph_mutator.cpp -o $@


src/consistency.o: src/consistency.cpp \
    include/consistency.hpp
	$(CXX) $(CXXFLAGS) -c src/consistency.cpp -o $@

src/data_race.o: src/data_race.cpp \
    include/data_race.hpp
	$(CXX) $(CXXFLAGS) -c src/data_race.cpp -o $@

src/skeleton_potential.o: src/skeleton_potential.cpp \
    include/skeleton_potential.hpp
	$(CXX) $(CXXFLAGS) -c src/skeleton_potential.cpp -o $@

src/skeleton_mo_footprint.o: src/skeleton_mo_footprint.cpp \
	include/skeleton_graph.hpp \
	include/skeleton_graph_mutator.hpp \
	include/skeleton_graph_mutator_wrapper.h
	$(CXX) $(CXXFLAGS) -c src/skeleton_mo_footprint.cpp -o $@

src/skeleton_rf_footprint.o: src/skeleton_rf_footprint.cpp \
	include/skeleton_rf_footprint.hpp \
	include/skeleton_graph.hpp \
	include/skeleton_graph_mutator.hpp \
	include/skeleton_graph_mutator_wrapper.h
	$(CXX) $(CXXFLAGS) -c src/skeleton_rf_footprint.cpp -o $@

src/skeleton_mutator_helper.o: src/skeleton_mutator_helper.cpp \
	include/skeleton_mutator_helper.hpp \
	include/static_program_abstraction.hpp \
	include/skeleton_graph.hpp \
	include/json.hpp
	$(CXX) $(CXXFLAGS) -c src/skeleton_mutator_helper.cpp -o $@

src/potential_nn.o: src/potential_nn.cpp \
	include/potential_nn.h \
	include/skeleton_potential.hpp
	$(CXX) $(CXXFLAGS) -c src/potential_nn.cpp -o $@

src/diversity_checker.o: src/diversity_checker.c \
	include/diversity_checker.h
	$(CC) $(CFLAGS) -c src/diversity_checker.c -o $@

src/event_pair_set.o: src/event_pair_set.c \
    include/event_pair_set.h
	$(CC) $(CFLAGS) -c src/event_pair_set.c -o $@

src/skeleton_queue_pruning.o: src/skeleton_queue_pruning.cpp \
	include/skeleton_queue_pruning.hpp \
	include/skeleton_graph.hpp \
	include/potential_nn.h
	$(CXX) $(CXXFLAGS) -c src/skeleton_queue_pruning.cpp -o $@

# --- Final target: sgf-fuzz ---
sgf-fuzz: $(COMM_HDR) include/sgf-fuzz.h \
          $(AFL_FUZZ_FILES:.c=.o) \
          src/sgf-common.o src/sgf-sharedmem.o src/sgf-forkserver.o \
          src/sgf-performance.o \
          src/skeleton_graph_mutator.o \
          src/consistency.o \
          src/data_race.o \
          src/skeleton_potential.o \
		  src/skeleton_mo_footprint.o \
		  src/skeleton_rf_footprint.o \
		  src/skeleton_mutator_helper.o \
          src/potential_nn.o \
          src/event_pair_set.o \
          src/diversity_checker.o \
          src/retgraph_shm.o \
          src/shm_next_events.o \
          src/sgf-queue-maxheap.o \
          src/sgf-queue-threshold-bucket.o \
          src/sgf-queue-runner-up.o \
          src/sgf-queue-maxheap-bucket.o \
          src/sgf-queue-dispatch.o \
          include/cmplog.h include/envs.h | test_x86
	$(CXX) $(CFLAGS) $(COMPILE_STATIC) $(CFLAGS_FLTO) $(SPECIAL_PERFORMANCE) \
	    $(AFL_FUZZ_FILES:.c=.o) \
	    src/sgf-common.o src/sgf-sharedmem.o src/sgf-forkserver.o \
	    src/sgf-performance.o \
	    src/skeleton_graph_mutator.o \
	    src/consistency.o \
	    src/data_race.o \
	    src/skeleton_potential.o \
	    src/skeleton_mo_footprint.o \
	    src/skeleton_rf_footprint.o \
	    src/potential_nn.o \
	    src/skeleton_mutator_helper.o \
	    src/skeleton_queue_pruning.o \
	    src/event_pair_set.o \
	    src/diversity_checker.o \
	    src/retgraph_shm.o \
	    src/shm_next_events.o \
	    src/sgf-queue-maxheap.o \
	    src/sgf-queue-threshold-bucket.o \
	    src/sgf-queue-runner-up.o \
	    src/sgf-queue-maxheap-bucket.o \
	    src/sgf-queue-dispatch.o \
	    -o $@ $(PYFLAGS) $(LDFLAGS) -lm



# # compiling the cpp files to get the .o files
# src/skeleton_graph_mutator.o: include/skeleton_graph_mutator_wrapper.h include/skeleton_graph_mutator.hpp src/skeleton_graph_mutator.cpp
# 	$(CXX) $(CXXFLAGS) -c $< -o $@

# # compiling the c files separately (doing this separately as a lot of AFL++ code performs type conversions which are valid in C but not in C++ eg. unsigned char* to char*)
# %.o: src/%.c $(COMM_HDR)
# 	$(CC) $(CFLAGS) $(CFLAGS_FLTO) $(SPECIAL_PERFORMANCE) -c $< -o $@

# sgf-fuzz: $(COMM_HDR) include/sgf-fuzz.h $(AFL_FUZZ_FILES) src/sgf-common.o src/sgf-sharedmem.o src/sgf-forkserver.o src/sgf-performance.o include/cmplog.h include/envs.h | test_x86
# 	$(CXX) $(CFLAGS) $(COMPILE_STATIC) $(CFLAGS_FLTO) $(SPECIAL_PERFORMANCE) $(AFL_FUZZ_FILES) src/sgf-common.o src/sgf-sharedmem.o src/sgf-forkserver.o src/sgf-performance.o src/skeleton_graph_mutator.o -o $@ $(PYFLAGS) $(LDFLAGS) -lm

ifdef IS_IOS
	@ldid -Sentitlements.plist $@ && echo "[+] Signed $@" || { echo "[-] Failed to sign $@"; }
endif

sgf-showmap: src/sgf-showmap.c src/sgf-fuzz-mutators.c src/sgf-fuzz-python.c src/sgf-common.o src/sgf-sharedmem.o src/sgf-forkserver.o src/sgf-performance.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $(COMPILE_STATIC) $(CFLAGS_FLTO) $(SPECIAL_PERFORMANCE) src/$@.c src/sgf-fuzz-mutators.c src/sgf-fuzz-python.c src/sgf-common.o src/sgf-sharedmem.o src/sgf-forkserver.o src/sgf-performance.o -o $@ $(PYFLAGS) $(LDFLAGS)
ifdef IS_IOS
	@ldid -Sentitlements.plist $@ && echo "[+] Signed $@" || { echo "[-] Failed to sign $@"; }
endif

sgf-tmin: src/sgf-tmin.c src/sgf-common.o src/sgf-sharedmem.o src/sgf-forkserver.o src/sgf-performance.o src/sgf-fuzz-python.o src/sgf-fuzz-mutators.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $(COMPILE_STATIC) $(CFLAGS_FLTO) $(SPECIAL_PERFORMANCE) src/$@.c src/sgf-common.o src/sgf-sharedmem.o src/sgf-forkserver.o src/sgf-performance.o src/sgf-fuzz-python.o src/sgf-fuzz-mutators.o -o $@ $(PYFLAGS) $(LDFLAGS)
ifdef IS_IOS
	@ldid -Sentitlements.plist $@ && echo "[+] Signed $@" || { echo "[-] Failed to sign $@"; }
endif

sgf-analyze: src/sgf-analyze.c src/sgf-common.o src/sgf-sharedmem.o src/sgf-performance.o src/sgf-forkserver.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $(COMPILE_STATIC) $(CFLAGS_FLTO) $(SPECIAL_PERFORMANCE) src/$@.c src/sgf-common.o src/sgf-sharedmem.o src/sgf-performance.o src/sgf-forkserver.o -o $@ $(LDFLAGS)
ifdef IS_IOS
	@ldid -Sentitlements.plist $@ && echo "[+] Signed $@" || { echo "[-] Failed to sign $@"; }
endif

sgf-gotcpu: src/sgf-gotcpu.c src/sgf-common.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $(COMPILE_STATIC) $(CFLAGS_FLTO) $(SPECIAL_PERFORMANCE) src/$@.c src/sgf-common.o -o $@ $(LDFLAGS)
ifdef IS_IOS
	@ldid -Sentitlements.plist $@ && echo "[+] Signed $@" || { echo "[-] Failed to sign $@"; }
endif

.PHONY: document
document:	sgf-fuzz-document

# document all mutations and only do one run (use with only one input file!)
sgf-fuzz-document: $(COMM_HDR) include/sgf-fuzz.h $(AFL_FUZZ_FILES) src/sgf-common.o src/sgf-sharedmem.o src/sgf-performance.o | test_x86
	$(CC) -D_DEBUG=\"1\" -D_AFL_DOCUMENT_MUTATIONS $(CFLAGS) $(CFLAGS_FLTO) $(AFL_FUZZ_FILES) src/sgf-common.o src/sgf-sharedmem.o src/sgf-forkserver.c src/sgf-performance.o -o sgf-fuzz-document $(PYFLAGS) $(LDFLAGS)
ifdef IS_IOS
	@ldid -Sentitlements.plist $@ && echo "[+] Signed $@" || { echo "[-] Failed to sign $@"; }
endif

test/unittests/unit_maybe_alloc.o : $(COMM_HDR) include/alloc-inl.h test/unittests/unit_maybe_alloc.c $(AFL_FUZZ_FILES)
	@$(CC) $(CFLAGS) $(ASAN_CFLAGS) -c test/unittests/unit_maybe_alloc.c -o test/unittests/unit_maybe_alloc.o

unit_maybe_alloc: test/unittests/unit_maybe_alloc.o
	@$(CC) $(CFLAGS) -Wl,--wrap=exit -Wl,--wrap=printf test/unittests/unit_maybe_alloc.o -o test/unittests/unit_maybe_alloc $(LDFLAGS) $(ASAN_LDFLAGS) -lcmocka
	./test/unittests/unit_maybe_alloc
ifdef IS_IOS
	@ldid -Sentitlements.plist $@ && echo "[+] Signed $@" || { echo "[-] Failed to sign $@"; }
endif

test/unittests/unit_hash.o : $(COMM_HDR) include/alloc-inl.h test/unittests/unit_hash.c $(AFL_FUZZ_FILES) src/sgf-performance.o
	@$(CC) $(CFLAGS) $(CFLAGS_FLTO) $(ASAN_CFLAGS) $(SPECIAL_PERFORMANCE) -c test/unittests/unit_hash.c -o test/unittests/unit_hash.o

unit_hash: test/unittests/unit_hash.o src/sgf-performance.o
	@$(CC) $(CFLAGS) $(CFLAGS_FLTO) $(ASAN_CFLAGS:-fno-lto=) $(SPECIAL_PERFORMANCE) -Wl,--wrap=exit -Wl,--wrap=printf $^ -o test/unittests/unit_hash $(LDFLAGS) $(ASAN_LDFLAGS:-fno-lto=) -lcmocka
	./test/unittests/unit_hash
ifdef IS_IOS
	@ldid -Sentitlements.plist $@ && echo "[+] Signed $@" || { echo "[-] Failed to sign $@"; }
endif

test/unittests/unit_rand.o : $(COMM_HDR) include/alloc-inl.h test/unittests/unit_rand.c $(AFL_FUZZ_FILES) src/sgf-performance.o
	@$(CC) $(CFLAGS) $(CFLAGS_FLTO) $(ASAN_CFLAGS) $(SPECIAL_PERFORMANCE) -c test/unittests/unit_rand.c -o test/unittests/unit_rand.o

unit_rand: test/unittests/unit_rand.o src/sgf-common.o src/sgf-performance.o
	@$(CC) $(CFLAGS) $(CFLAGS_FLTO) $(ASAN_CFLAGS:-fno-lto=) $(SPECIAL_PERFORMANCE) -Wl,--wrap=exit -Wl,--wrap=printf $^ -o test/unittests/unit_rand $(LDFLAGS) $(ASAN_LDFLAGS:-fno-lto=) -lcmocka
	./test/unittests/unit_rand
ifdef IS_IOS
	@ldid -Sentitlements.plist $@ && echo "[+] Signed $@" || { echo "[-] Failed to sign $@"; }
endif

test/unittests/unit_list.o : $(COMM_HDR) include/list.h test/unittests/unit_list.c $(AFL_FUZZ_FILES)
	@$(CC) $(CFLAGS) $(ASAN_CFLAGS) -c test/unittests/unit_list.c -o test/unittests/unit_list.o

unit_list: test/unittests/unit_list.o
	@$(CC) $(CFLAGS) $(ASAN_CFLAGS) -Wl,--wrap=exit -Wl,--wrap=printf test/unittests/unit_list.o -o test/unittests/unit_list  $(LDFLAGS) $(ASAN_LDFLAGS) -lcmocka
	./test/unittests/unit_list
ifdef IS_IOS
	@ldid -Sentitlements.plist $@ && echo "[+] Signed $@" || { echo "[-] Failed to sign $@"; }
endif

test/unittests/unit_preallocable.o : $(COMM_HDR) include/alloc-inl.h test/unittests/unit_preallocable.c $(AFL_FUZZ_FILES)
	@$(CC) $(CFLAGS) $(ASAN_CFLAGS) -c test/unittests/unit_preallocable.c -o test/unittests/unit_preallocable.o

unit_preallocable: test/unittests/unit_preallocable.o
	@$(CC) $(CFLAGS) $(ASAN_CFLAGS) -Wl,--wrap=exit -Wl,--wrap=printf test/unittests/unit_preallocable.o -o test/unittests/unit_preallocable $(LDFLAGS) $(ASAN_LDFLAGS) -lcmocka
	./test/unittests/unit_preallocable
ifdef IS_IOS
	@ldid -Sentitlements.plist $@ && echo "[+] Signed $@" || { echo "[-] Failed to sign $@"; }
endif

.PHONY: clean
clean:
	rm -rf $(PROGS) sgf-fuzz-document as sgf-as afl-g++ sgf-clang sgf-clang++ *.o src/*.o *~ a.out core core.[1-9][0-9]* *.stackdump .test .test1 .test2 test-instr .test-instr0 .test-instr1 afl-cs-proxy afl-qemu-trace afl-gcc-fast afl-g++-fast ld *.so *.8 .afl-* afl-gcc afl-g++ sgf-clang sgf-clang++ *.dSYM lib*.a

