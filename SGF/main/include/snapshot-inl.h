/*
   american fuzzy lop++ - snapshot helpers routines
   ------------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eissfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

 */

// From AFL-Snapshot-LKM/include/sgf_snapshot.h (must be kept synced)

#include <sys/ioctl.h>
#include <stdlib.h>
#include <fcntl.h>

#define SGF_SNAPSHOT_FILE_NAME "/dev/sgf_snapshot"

#define SGF_SNAPSHOT_IOCTL_MAGIC 44313

#define SGF_SNAPSHOT_IOCTL_DO _IO(SGF_SNAPSHOT_IOCTL_MAGIC, 1)
#define SGF_SNAPSHOT_IOCTL_CLEAN _IO(SGF_SNAPSHOT_IOCTL_MAGIC, 2)
#define SGF_SNAPSHOT_EXCLUDE_VMRANGE \
  _IOR(SGF_SNAPSHOT_IOCTL_MAGIC, 3, struct sgf_snapshot_vmrange_args *)
#define SGF_SNAPSHOT_INCLUDE_VMRANGE \
  _IOR(SGF_SNAPSHOT_IOCTL_MAGIC, 4, struct sgf_snapshot_vmrange_args *)
#define SGF_SNAPSHOT_IOCTL_TAKE _IOR(SGF_SNAPSHOT_IOCTL_MAGIC, 5, int)
#define SGF_SNAPSHOT_IOCTL_RESTORE _IO(SGF_SNAPSHOT_IOCTL_MAGIC, 6)

// Trace new mmaped ares and unmap them on restore.
#define SGF_SNAPSHOT_MMAP 1
// Do not snapshot any page (by default all writeable not-shared pages
// are shanpshotted.
#define SGF_SNAPSHOT_BLOCK 2
// Snapshot file descriptor state, close newly opened descriptors
#define SGF_SNAPSHOT_FDS 4
// Snapshot registers state
#define SGF_SNAPSHOT_REGS 8
// Perform a restore when exit_group is invoked
#define SGF_SNAPSHOT_EXIT 16
// TODO(andrea) allow not COW snapshots (high perf on small processes)
// Disable COW, restore all the snapshotted pages
#define SGF_SNAPSHOT_NOCOW 32
// Do not snapshot Stack pages
#define SGF_SNAPSHOT_NOSTACK 64

struct sgf_snapshot_vmrange_args {

  unsigned long start, end;

};

static int sgf_snapshot_dev_fd;

static int afl_snapshot_init(void) {

  sgf_snapshot_dev_fd = open(SGF_SNAPSHOT_FILE_NAME, 0);
  return sgf_snapshot_dev_fd;

}

static void afl_snapshot_exclude_vmrange(void *start, void *end) {

  struct sgf_snapshot_vmrange_args args = {(unsigned long)start,
                                           (unsigned long)end};
  ioctl(sgf_snapshot_dev_fd, SGF_SNAPSHOT_EXCLUDE_VMRANGE, &args);

}

static void afl_snapshot_include_vmrange(void *start, void *end) {

  struct sgf_snapshot_vmrange_args args = {(unsigned long)start,
                                           (unsigned long)end};
  ioctl(sgf_snapshot_dev_fd, SGF_SNAPSHOT_INCLUDE_VMRANGE, &args);

}

static int afl_snapshot_take(int config) {

  return ioctl(sgf_snapshot_dev_fd, SGF_SNAPSHOT_IOCTL_TAKE, config);

}

static int afl_snapshot_do(void) {

  return ioctl(sgf_snapshot_dev_fd, SGF_SNAPSHOT_IOCTL_DO);

}

static void afl_snapshot_restore(void) {

  ioctl(sgf_snapshot_dev_fd, SGF_SNAPSHOT_IOCTL_RESTORE);

}

static void afl_snapshot_clean(void) {

  ioctl(sgf_snapshot_dev_fd, SGF_SNAPSHOT_IOCTL_CLEAN);

}

