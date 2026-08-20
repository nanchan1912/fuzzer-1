/*
   american fuzzy lop++ - initialization related routines
   ------------------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eissfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "sgf-fuzz.h"
#include "common.h"
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include "cmplog.h"

//for the parse_program_abstraction_file function
#include "skeleton_graph_mutator_wrapper.h"


#ifdef HAVE_AFFINITY

/* bind process to a specific cpu. Returns 0 on failure. */

static u8 bind_cpu(sgf_state_t *sgf, s32 cpuid) {

  #if defined(__linux__) || defined(__FreeBSD__) || defined(__DragonFly__)
  cpu_set_t c;
  #elif defined(__NetBSD__)
  cpuset_t *c;
  #elif defined(__sun)
  psetid_t c;
  #endif

  sgf->cpu_aff = cpuid;

  #if defined(__linux__) || defined(__FreeBSD__) || defined(__DragonFly__)

  CPU_ZERO(&c);
  CPU_SET(cpuid, &c);

  #elif defined(__NetBSD__)

  c = cpuset_create();
  if (c == NULL) { PFATAL("cpuset_create failed"); }
  cpuset_set(cpuid, c);

  #elif defined(__sun)

  pset_create(&c);
  if (pset_assign(c, cpuid, NULL)) { PFATAL("pset_assign failed"); }

  #endif

  #if defined(__linux__)

  return (sched_setaffinity(0, sizeof(c), &c) == 0);

  #elif defined(__FreeBSD__) || defined(__DragonFly__)

  return (pthread_setaffinity_np(pthread_self(), sizeof(c), &c) == 0);

  #elif defined(__NetBSD__)

  if (pthread_setaffinity_np(pthread_self(), cpuset_size(c), c)) {

    cpuset_destroy(c);
    return 0;

  }

  cpuset_destroy(c);
  return 1;

  #elif defined(__sun)

  if (pset_bind(c, P_PID, getpid(), NULL)) {

    pset_destroy(c);
    return 0;

  }

  pset_destroy(c);
  return 1;

  #else

  // this will need something for other platforms
  // TODO: Solaris/Illumos has processor_bind ... might worth a try
  WARNF("Cannot bind to CPU yet on this platform.");
  return 1;

  #endif

}

/* Build a list of processes bound to specific cores. Returns -1 if nothing
   can be found. Assumes an upper bound of 4k CPUs. */

void bind_to_free_cpu(sgf_state_t *sgf) {

  u8  cpu_used[4096] = {0};
  u8  lockfile[PATH_MAX] = "";
  s32 i;

  if (sgf->sgf_env.sgf_no_affinity && !sgf->sgf_env.sgf_try_affinity) {

    if (sgf->cpu_to_bind != -1) {

      FATAL("-b and SGF_NO_AFFINITY are mututally exclusive.");

    }

    WARNF("Not binding to a CPU core (SGF_NO_AFFINITY set).");
  #ifdef __linux__
    if (sgf->fsrv.nyx_mode) { sgf->fsrv.nyx_bind_cpu_id = 0; }
  #endif
    return;

  }

  if (sgf->cpu_to_bind != -1) {

    if (!bind_cpu(sgf, sgf->cpu_to_bind)) {

      if (sgf->sgf_env.sgf_try_affinity) {

        WARNF(
            "Could not bind to requested CPU %d! Make sure you passed a valid "
            "-b.",
            sgf->cpu_to_bind);

      } else {

        FATAL(
            "Could not bind to requested CPU %d! Make sure you passed a valid "
            "-b.",
            sgf->cpu_to_bind);

      }

    } else {

      OKF("CPU binding request using -b %d successful.", sgf->cpu_to_bind);
  #ifdef __linux__
      if (sgf->fsrv.nyx_mode) { sgf->fsrv.nyx_bind_cpu_id = sgf->cpu_to_bind; }
  #endif

    }

    return;

  }

  if (sgf->cpu_core_count < 2) { return; }

  if (sgf->sync_id) {

    s32 lockfd, first = 1;

    snprintf(lockfile, sizeof(lockfile), "%s/.affinity_lock", sgf->sync_dir);
    setenv(CPU_AFFINITY_ENV_VAR, lockfile, 1);

    do {

      if ((lockfd = open(lockfile, O_RDWR | O_CREAT | O_EXCL,
                         DEFAULT_PERMISSION)) < 0) {

        if (first) {

          WARNF("CPU affinity lock file present, waiting ...");
          first = 0;

        }

        usleep(1000);

      }

    } while (lockfd < 0);

    close(lockfd);

  }

  #if defined(__linux__)

  DIR           *d;
  struct dirent *de;
  d = opendir("/proc");

  if (!d) {

    if (lockfile[0]) unlink(lockfile);
    WARNF("Unable to access /proc - can't scan for free CPU cores.");
    return;

  }

  ACTF("Checking CPU core loadout...");

  /* Scan all /proc/<pid>/status entries, checking for Cpus_allowed_list.
     Flag all processes bound to a specific CPU using cpu_used[]. This will
     fail for some exotic binding setups, but is likely good enough in almost
     all real-world use cases. */

  while ((de = readdir(d))) {

    u8    fn[PATH_MAX];
    FILE *f;
    u8    tmp[MAX_LINE];
    u8    has_vmsize = 0;

    if (!isdigit(de->d_name[0])) { continue; }

    snprintf(fn, PATH_MAX, "/proc/%s/status", de->d_name);

    if (!(f = fopen(fn, "r"))) { continue; }

    while (fgets(tmp, MAX_LINE, f)) {

      u32 hval;

      /* Processes without VmSize are probably kernel tasks. */

      if (!strncmp(tmp, "VmSize:\t", 8)) { has_vmsize = 1; }

      if (!strncmp(tmp, "Cpus_allowed_list:\t", 19) && !strchr(tmp, '-') &&
          !strchr(tmp, ',') && sscanf(tmp + 19, "%u", &hval) == 1 &&
          hval < sizeof(cpu_used) && has_vmsize) {

        cpu_used[hval] = 1;
        break;

      }

    }

    fclose(f);

  }

  closedir(d);

  #elif defined(__FreeBSD__) || defined(__DragonFly__)

  struct kinfo_proc *procs;
  size_t             nprocs;
  size_t             proccount;
  int                s_name[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL};
  size_t             s_name_l = sizeof(s_name) / sizeof(s_name[0]);

  if (sysctl(s_name, s_name_l, NULL, &nprocs, NULL, 0) != 0) {

    if (lockfile[0]) unlink(lockfile);
    return;

  }

  proccount = nprocs / sizeof(*procs);
  nprocs = nprocs * 4 / 3;

  procs = ck_alloc(nprocs);
  if (sysctl(s_name, s_name_l, procs, &nprocs, NULL, 0) != 0) {

    if (lockfile[0]) unlink(lockfile);
    ck_free(procs);
    return;

  }

  for (i = 0; i < (s32)proccount; i++) {

    #if defined(__FreeBSD__)

    if (!strcmp(procs[i].ki_comm, "idle")) continue;

    // fix when ki_oncpu = -1
    s32 oncpu;
    oncpu = procs[i].ki_oncpu;
    if (oncpu == -1) oncpu = procs[i].ki_lastcpu;

    if (oncpu != -1 && oncpu < (s32)sizeof(cpu_used) && procs[i].ki_pctcpu > 60)
      cpu_used[oncpu] = 1;

    #elif defined(__DragonFly__)

    if (procs[i].kp_lwp.kl_cpuid < (s32)sizeof(cpu_used) &&
        procs[i].kp_lwp.kl_pctcpu > 10)
      cpu_used[procs[i].kp_lwp.kl_cpuid] = 1;

    #endif

  }

  ck_free(procs);

  #elif defined(__NetBSD__)

  struct kinfo_proc2 *procs;
  size_t              nprocs;
  size_t              proccount;
  int                 s_name[] = {

      CTL_KERN, KERN_PROC2, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc2), 0};
  size_t s_name_l = sizeof(s_name) / sizeof(s_name[0]);

  if (sysctl(s_name, s_name_l, NULL, &nprocs, NULL, 0) != 0) {

    if (lockfile[0]) unlink(lockfile);
    return;

  }

  proccount = nprocs / sizeof(struct kinfo_proc2);
  procs = ck_alloc(nprocs * sizeof(struct kinfo_proc2));
  s_name[5] = proccount;

  if (sysctl(s_name, s_name_l, procs, &nprocs, NULL, 0) != 0) {

    if (lockfile[0]) unlink(lockfile);
    ck_free(procs);
    return;

  }

  for (i = 0; i < (s32)proccount; i++) {

    if (procs[i].p_cpuid < sizeof(cpu_used) && procs[i].p_pctcpu > 0)
      cpu_used[procs[i].p_cpuid] = 1;

  }

  ck_free(procs);

  #elif defined(__sun)

  kstat_named_t *n;
  kstat_ctl_t   *m;
  kstat_t       *k;
  cpu_stat_t     cs;
  u32            ncpus;

  m = kstat_open();

  if (!m) FATAL("kstat_open failed");

  k = kstat_lookup(m, "unix", 0, "system_misc");

  if (!k) {

    if (lockfile[0]) unlink(lockfile);
    kstat_close(m);
    return;

  }

  if (kstat_read(m, k, NULL)) {

    if (lockfile[0]) unlink(lockfile);
    kstat_close(m);
    return;

  }

  n = kstat_data_lookup(k, "ncpus");
  ncpus = n->value.i32;

  if (ncpus > sizeof(cpu_used)) ncpus = sizeof(cpu_used);

  for (i = 0; i < (s32)ncpus; i++) {

    k = kstat_lookup(m, "cpu_stat", i, NULL);
    if (kstat_read(m, k, &cs)) {

      if (lockfile[0]) unlink(lockfile);
      kstat_close(m);
      return;

    }

    if (cs.cpu_sysinfo.cpu[CPU_IDLE] > 0) continue;

    if (cs.cpu_sysinfo.cpu[CPU_USER] > 0 || cs.cpu_sysinfo.cpu[CPU_KERNEL] > 0)
      cpu_used[i] = 1;

  }

  kstat_close(m);

  #else
    #warning \
        "For this platform we do not have free CPU binding code yet. If possible, please supply a PR to https://github.com/AFLplusplus/AFLplusplus"
  #endif

  #if !defined(__aarch64__) && !defined(__arm__) && !defined(__arm64__)

  for (i = 0; i < sgf->cpu_core_count; i++) {

  #else

  /* many ARM devices have performance and efficiency cores, the slower
     efficiency cores seem to always come first */

  for (i = sgf->cpu_core_count - 1; i > -1; i--) {

  #endif

    if (cpu_used[i]) { continue; }

    OKF("Found a free CPU core, try binding to #%u.", i);

    if (bind_cpu(sgf, i)) {

  #ifdef __linux__
      if (sgf->fsrv.nyx_mode) { sgf->fsrv.nyx_bind_cpu_id = i; }
  #endif
      /* Success :) */
      break;

    }

    WARNF("setaffinity failed to CPU %d, trying next CPU", i);

  }

  if (lockfile[0]) unlink(lockfile);

  if (i == sgf->cpu_core_count || i == -1) {

    SAYF("\n" cLRD "[-] " cRST
         "Uh-oh, looks like all %d CPU cores on your system are allocated to\n"
         "    other instances of sgf-fuzz (or similar CPU-locked tasks). "
         "Starting\n"
         "    another fuzzer on this machine is probably a bad plan.\n"
         "%s",
         sgf->cpu_core_count,
         sgf->sgf_env.sgf_try_affinity ? ""
                                       : "    If you are sure, you can set "
                                         "SGF_NO_AFFINITY and try again.\n");

    if (!sgf->sgf_env.sgf_try_affinity) { FATAL("No more free CPU cores"); }

  }

}

#endif                                                     /* HAVE_AFFINITY */

/* transforms spaces in a string to underscores (inplace) */

static void no_spaces(u8 *string) {

  if (string) {

    u8 *ptr = string;
    while (*ptr != 0) {

      if (*ptr == ' ') { *ptr = '_'; }
      ++ptr;

    }

  }

}

/* Shuffle an array of pointers. Might be slightly biased. */

static void shuffle_ptrs(sgf_state_t *sgf, void **ptrs, u32 cnt) {

  u32 i;

  for (i = 0; i < cnt - 2; ++i) {

    u32   j = i + rand_below(sgf, cnt - i);
    void *s = ptrs[i];
    ptrs[i] = ptrs[j];
    ptrs[j] = s;

  }

}

/* Read all testcases from foreign input directories, then queue them for
   testing. Called at sync intervals. Use env SGF_IMPORT_FIRST to sync at
   startup (but may delay the startup depending on the amount of fails
   and speed of execution).
   Does not descend into subdirectories! */

void read_foreign_testcases(sgf_state_t *sgf, int first) {

  if (!sgf->foreign_sync_cnt) return;

  struct dirent **nl;
  s32             nl_cnt;
  u32             i, iter;

  u8 val_buf[2][STRINGIFY_VAL_SIZE_MAX];
  u8 foreign_name[16];

  for (iter = 0; iter < sgf->foreign_sync_cnt; iter++) {

    if (sgf->foreign_syncs[iter].dir && sgf->foreign_syncs[iter].dir[0]) {

      if (first) ACTF("Scanning '%s'...", sgf->foreign_syncs[iter].dir);
      time_t mtime_max = 0;

      u8 *name = strrchr(sgf->foreign_syncs[iter].dir, '/');
      if (!name) {

        name = sgf->foreign_syncs[iter].dir;

      } else {

        ++name;

      }

      if (!strcmp(name, "queue") || !strcmp(name, "out") ||
          !strcmp(name, "default")) {

        snprintf(foreign_name, sizeof(foreign_name), "foreign_%u", iter);

      } else {

        snprintf(foreign_name, sizeof(foreign_name), "%s_%u", name, iter);

      }

      /* We do not use sorting yet and do a more expensive mtime check instead.
         a mtimesort() implementation would be better though. */

      nl_cnt = scandir(sgf->foreign_syncs[iter].dir, &nl, NULL, NULL);

      if (nl_cnt < 0) {

        if (first) {

          WARNF("Unable to open directory '%s'", sgf->foreign_syncs[iter].dir);
          sleep(1);

        }

        continue;

      }

      if (nl_cnt == 0) {

        if (first) {

          WARNF("directory %s is currently empty",
                sgf->foreign_syncs[iter].dir);

        }

        free(nl);
        continue;

      }

      /* Show stats */

      snprintf(sgf->stage_name_buf, STAGE_BUF_SIZE, "foreign sync %u", iter);

      sgf->stage_name = sgf->stage_name_buf;
      sgf->stage_cur = 0;
      sgf->stage_max = 0;

      show_stats(sgf);

      for (i = 0; i < (u32)nl_cnt; ++i) {

        struct stat st;

        u8 *fn2 =
            alloc_printf("%s/%s", sgf->foreign_syncs[iter].dir, nl[i]->d_name);

        if (unlikely(stat(fn2, &st) || access(fn2, R_OK))) {

          if (first) PFATAL("Unable to access '%s'", fn2);
          ck_free(fn2);
          continue;

        }

        /* we detect new files by their mtime */
        if (likely(st.st_mtime <= sgf->foreign_syncs[iter].mtime)) {

          ck_free(fn2);
          continue;

        }

        /* This also takes care of . and .. */

        if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn2, "/README.txt")) {

          ck_free(fn2);
          continue;

        }

        if (st.st_size > MAX_FILE) {

          if (first) {

            WARNF(
                "Test case '%s' is too big (%s, limit is %s), skipping", fn2,
                stringify_mem_size(val_buf[0], sizeof(val_buf[0]), st.st_size),
                stringify_mem_size(val_buf[1], sizeof(val_buf[1]), MAX_FILE));

          }

          ck_free(fn2);
          continue;

        }

        // lets do not use add_to_queue(sgf, fn2, st.st_size, 0);
        // as this could add duplicates of the startup input corpus

        int fd = open(fn2, O_RDONLY);
        ck_free(fn2);

        if (fd < 0) { continue; }

        u8  fault;
        u8 *mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

        if (mem == MAP_FAILED) {

          close(fd);
          continue;

        }

        u32 len = write_to_testcase(sgf, (void **)&mem, st.st_size, 1);
        fault = fuzz_run_target(sgf, &sgf->fsrv, sgf->fsrv.exec_tmout);
        sgf->syncing_party = foreign_name;
        sgf->foreign_file = nl[i]->d_name;


        // REVISIT: check if 0, MAP_SIZE is correct here
        sgf->queued_imported += save_if_interesting(sgf, mem, len, fault, 0, MAP_SIZE);

        munmap(mem, st.st_size);
        close(fd);

        if (st.st_mtime > mtime_max) { mtime_max = st.st_mtime; }
        show_stats(sgf);

      }

      if (mtime_max > sgf->foreign_syncs[iter].mtime) {

        sgf->foreign_syncs[iter].mtime = mtime_max;

      }

      for (i = 0; i < (u32)nl_cnt; ++i) {

        free(nl[i]);                                         /* not tracked */

      }

      free(nl);                                              /* not tracked */

    }

  }

  sgf->foreign_file = NULL;
  sgf->syncing_party = 0;

  if (first) {

    sgf->last_find_time = 0;
    sgf->queued_at_start = sgf->queued_items;

  }

}

/* Read all testcases from the input directory, then queue them for testing.
   Called at startup. */

void read_testcases(sgf_state_t *sgf, u8 *directory) {
  // calling this function to send the .eg file path to skeleton_graph_mutator.cpp
  parse_program_abstraction_file(sgf->static_program_abstraction);

  struct dirent **nl;
  s32             nl_cnt, subdirs = 1;
  u32             i;
  u8             *fn1, *dir = directory;
  u8              val_buf[2][STRINGIFY_VAL_SIZE_MAX];

  /* Auto-detect non-in-place resumption attempts. */

  if (dir == NULL) {

    fn1 = alloc_printf("%s/queue", sgf->in_dir);
    if (!access(fn1, F_OK)) {

      sgf->in_dir = fn1;
      subdirs = 0;

    } else {

      ck_free(fn1);

    }

    dir = sgf->in_dir;

  }

  ACTF("Scanning '%s'...", dir);

  /* We use scandir() + alphasort() rather than readdir() because otherwise,
     the ordering of test cases would vary somewhat randomly and would be
     difficult to control. */

  nl_cnt = scandir(dir, &nl, NULL, alphasort);

  if (nl_cnt < 0 && directory == NULL) {

    if (errno == ENOENT || errno == ENOTDIR) {

      SAYF("\n" cLRD "[-] " cRST
           "The input directory does not seem to be valid - try again. The "
           "fuzzer needs\n"
           "    one or more test case to start with - ideally, a small file "
           "under 1 kB\n"
           "    or so. The cases must be stored as regular files directly in "
           "the input\n"
           "    directory.\n");

    }

    PFATAL("Unable to open '%s'", dir);

  }

  if (unlikely(sgf->old_seed_selection && sgf->shuffle_queue && nl_cnt > 1)) {

    ACTF("Shuffling queue...");
    shuffle_ptrs(sgf, (void **)nl, nl_cnt);

  }

  if (nl_cnt) {

    u32 done = 0;
    i = 0;

    do {

      struct stat st;
      u8          dfn[PATH_MAX];
      snprintf(dfn, PATH_MAX, "%s/.state/deterministic_done/%s", sgf->in_dir,
               nl[i]->d_name);
      u8 *fn2 = alloc_printf("%s/%s", dir, nl[i]->d_name);

      u8 passed_det = 0;

      if (stat(fn2, &st) || access(fn2, R_OK)) {

        PFATAL("Unable to access '%s'", fn2);

      }

      /* obviously we want to skip "descending" into . and .. directories,
         however it is a good idea to skip also directories that start with
         a dot */
      if (subdirs && S_ISDIR(st.st_mode) && nl[i]->d_name[0] != '.') {

        free(nl[i]);                                         /* not tracked */
        read_testcases(sgf, fn2);
        ck_free(fn2);
        goto next_entry;

      }

      free(nl[i]);

      if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn2, "/README.txt")) {

        ck_free(fn2);
        goto next_entry;

      }

      if (st.st_size > MAX_FILE) {

        WARNF("Test case '%s' is too big (%s, limit is %s), partial reading",
              fn2,
              stringify_mem_size(val_buf[0], sizeof(val_buf[0]), st.st_size),
              stringify_mem_size(val_buf[1], sizeof(val_buf[1]), MAX_FILE));

      }

      /* Check for metadata that indicates that deterministic fuzzing
         is complete for this entry. We don't want to repeat deterministic
         fuzzing when resuming aborted scans, because it would be pointless
         and probably very time-consuming. */
      update_mo_freq_from_seed(fn2);

      if (!access(dfn, F_OK)) { passed_det = 1; }

      add_to_queue(sgf, fn2, st.st_size >= MAX_FILE ? MAX_FILE : st.st_size,
                   passed_det);
      
      // The skeleton graph is read already, 
      // if we don't set it for the queue entry, 
      // it will default to reading from json again.
      // - Hardik
      if (sgf->queue_top && sgf->queue_top->graph_data) {
        sgf->queue_top->graph_data->skeleton_graph = read_from_json(fn2);
      }

      if (unlikely(sgf->shm.cmplog_mode)) {

        if (sgf->cmplog_lvl == 1) {

          if (!sgf->cmplog_max_filesize ||
              sgf->cmplog_max_filesize < st.st_size) {

            sgf->cmplog_max_filesize = st.st_size;

          }

        } else if (sgf->cmplog_lvl == 2) {

          if (!sgf->cmplog_max_filesize ||
              sgf->cmplog_max_filesize > st.st_size) {

            sgf->cmplog_max_filesize = st.st_size;

          }

        }

      }

    next_entry:
      if (unlikely(++i >= (u32)nl_cnt)) { done = 1; }

    } while (!done);

  }

  free(nl);                                                  /* not tracked */

  if (!sgf->queued_items && directory == NULL) {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like there are no valid test cases in the input directory! The "
         "fuzzer\n"
         "    needs one or more test case to start with - ideally, a small "
         "file under\n"
         "    1 kB or so. The cases must be stored as regular files directly "
         "in the\n"
         "    input directory.\n");

    FATAL("No usable test cases in '%s'", sgf->in_dir);

  }

  if (unlikely(sgf->shm.cmplog_mode)) {

    if (sgf->cmplog_max_filesize < 1024) {

      sgf->cmplog_max_filesize = 1024;

    } else {

      sgf->cmplog_max_filesize = (((sgf->cmplog_max_filesize >> 10) + 1) << 10);

    }

  }

  sgf->last_find_time = 0;
  sgf->queued_at_start = sgf->queued_items;

}

/* Perform dry run of all test cases to confirm that the app is working as
   expected. This is done only for the initial inputs, and only once. */

void perform_dry_run(sgf_state_t *sgf) {

  struct queue_entry *q;
  u32                 cal_failures = 0, idx;
  u8                 *use_mem, done = 0;

  if (sgf->in_place_resume) {

    idx = sgf->queued_items;

  } else {

    idx = 0;

  }

  do {

    if (sgf->in_place_resume) { --idx; }

    q = sgf->queue_buf[idx];
    if (unlikely(!q || q->disabled)) { continue; }

    u8  res;
    s32 fd;

    if (unlikely(!q->len)) {

      WARNF("Skipping 0-sized entry in queue (%s)", q->fname);
      continue;

    }

    if (sgf->sgf_env.sgf_cmplog_only_new) { q->colorized = CMPLOG_LVL_MAX; }

    u8 *fn = strrchr(q->fname, '/') + 1;

    ACTF("Attempting dry run with '%s'...", fn);

    fd = open(q->fname, O_RDONLY);
    if (fd < 0) { PFATAL("Unable to open '%s'", q->fname); }

    u32 read_len = MIN(q->len, (u32)MAX_FILE);
    use_mem = afl_realloc(SGF_BUF_PARAM(in), read_len);
    ck_read(fd, use_mem, read_len, q->fname);

    close(fd);

    res = calibrate_case(sgf, q, use_mem, 0, 1);

    /* For AFLFast schedules we update the queue entry */
    if (unlikely(sgf->schedule >= FAST && sgf->schedule <= RARE) &&
        likely(q->exec_cksum)) {

      q->n_fuzz_entry = q->exec_cksum % N_FUZZ_SIZE;

    }

    if (sgf->stop_soon) { return; }

    if (res == sgf->crash_mode || res == FSRV_RUN_NOBITS) {

      SAYF(cGRA
           "    len = %u, map size = %u, exec speed = %llu us, hash = "
           "%016llx\n" cRST,
           q->len, q->bitmap_size, q->exec_us, q->exec_cksum);

    }

    switch (res) {

      case FSRV_RUN_OK:

        if (sgf->crash_mode) { FATAL("Test case '%s' does *NOT* crash", fn); }

        break;

      case FSRV_RUN_TMOUT:

        if (sgf->timeout_given && !sgf->sgf_env.sgf_exit_on_seed_issues) {

          /* if we have a timeout but a timeout value was given then always
             skip. The '+' meaning has been changed! */
          WARNF("Test case results in a timeout (skipping)");
          ++cal_failures;
          q->cal_failed = CAL_CHANCES;
          q->disabled = 1;
          q->perf_score = 0;

          if (!q->was_fuzzed) {

            q->was_fuzzed = 1;
            sgf->reinit_table = 1;
            --sgf->pending_not_fuzzed;
            --sgf->active_items;

          }

          break;

        } else {

          static int say_once = 0;

          if (!say_once) {

            SAYF(
                "\n" cLRD "[-] " cRST
                "The program took more than %u ms to process one of the "
                "initial "
                "test cases.\n"
                "    This is bad news; raising the limit with the -t option is "
                "possible, but\n"
                "    will probably make the fuzzing process extremely slow.\n\n"

                "    If this test case is just a fluke, the other option is to "
                "just avoid it\n"
                "    altogether, and find one that is less of a CPU hog.\n",
                sgf->fsrv.exec_tmout);

            if (!sgf->sgf_env.sgf_ignore_seed_problems) {

              FATAL("Test case '%s' results in a timeout", fn);

            }

            say_once = 1;

          }

          if (unlikely(!q->was_fuzzed)) {

            q->was_fuzzed = 1;
            sgf->reinit_table = 1;
            --sgf->pending_not_fuzzed;
            --sgf->active_items;

          }

          q->disabled = 1;
          q->perf_score = 0;

          WARNF("Test case '%s' results in a timeout, skipping", fn);
          break;

        }

      case FSRV_RUN_CRASH:

        if (sgf->crash_mode) { break; }

        const u8 *msg_exit_code = "";

        if (sgf->fsrv.uses_asan && !sgf->fsrv.last_kill_signal) {

          if ((sgf->fsrv.uses_asan & 4) &&
              sgf->fsrv.last_exit_code == MSAN_ERROR) {

            msg_exit_code =
                "    - The test case terminated with the exit code that is "
                "used by MSAN to\n"
                "      indicate an error. This is counted as a crash by "
                "sgf-fuzz because you\n"
                "      have compiled the target with MSAN enabled. This could "
                "be a false\n"
                "      positive if the program returns this exit code under "
                "normal operation.\n"
                "      In that case, either disable MSAN or change the test "
                "case or program\n"
                "      to avoid generating this exit code.\n\n";

          } else if ((sgf->fsrv.uses_asan & 2) &&

                     sgf->fsrv.last_exit_code == LSAN_ERROR) {

            msg_exit_code =
                "    - The test case terminated with the exit code that is "
                "used by LSAN to\n"
                "      indicate an error. This is counted as a crash by "
                "sgf-fuzz because you\n"
                "      have compiled the target with LSAN enabled. This could "
                "be a false\n"
                "      positive if the program returns this exit code under "
                "normal operation.\n"
                "      In that case, either disable LSAN or change the test "
                "case or program\n"
                "      to avoid generating this exit code.\n\n";

          }

        }

        if (sgf->fsrv.mem_limit) {

          u8 val_buf[STRINGIFY_VAL_SIZE_MAX];

          SAYF("\n" cLRD "[-] " cRST
               "Oops, the program crashed with one of the test cases provided. "
               "There are\n"
               "    several possible explanations:\n\n"

               "    - The test case causes known crashes under normal working "
               "conditions. If\n"
               "      so, please remove it. The fuzzer should be seeded with "
               "interesting\n"
               "      inputs - but not ones that cause an outright crash.\n\n"
               "%s"

               "    - The current memory limit (%s) is too low for this "
               "program, causing\n"
               "      it to die due to OOM when parsing valid files. To fix "
               "this, try\n"
               "      bumping it up with the -m setting in the command line. "
               "If in doubt,\n"
               "      try something along the lines of:\n\n"

               MSG_ULIMIT_USAGE
               " /path/to/binary [...] <testcase )\n\n"

               "      Tip: you can use https://jwilk.net/software/recidivm to\n"
               "      estimate the required amount of virtual memory for the "
               "binary. Also,\n"
               "      if you are using ASAN, set '-m 0'.\n\n"

               "    - In QEMU persistent mode the selected address(es) for the "
               "loop are not\n"
               "      properly cleaning up variables and memory. Try adding\n"
               "      SGF_QEMU_PERSISTENT_GPR=1 or select better addresses in "
               "the binary.\n\n"

               MSG_FORK_ON_APPLE

               "    - Least likely, there is a horrible bug in the fuzzer. If "
               "other options\n"
               "      fail, poke the Awesome Fuzzing Discord for "
               "troubleshooting tips.\n",
               msg_exit_code,
               stringify_mem_size(val_buf, sizeof(val_buf),
                                  sgf->fsrv.mem_limit << 20),
               sgf->fsrv.mem_limit - 1);

        } else {

          SAYF("\n" cLRD "[-] " cRST
               "Oops, the program crashed with one of the test cases provided. "
               "There are\n"
               "    several possible explanations:\n\n"

               "    - The test case causes known crashes under normal working "
               "conditions. If\n"
               "      so, please remove it. The fuzzer should be seeded with "
               "interesting\n"
               "      inputs - but not ones that cause an outright crash.\n\n"
               "%s"

               "    - In QEMU persistent mode the selected address(es) for the "
               "loop are not\n"
               "      properly cleaning up variables and memory. Try adding\n"
               "      SGF_QEMU_PERSISTENT_GPR=1 or select better addresses in "
               "the binary.\n\n"

               MSG_FORK_ON_APPLE

               "    - Least likely, there is a horrible bug in the fuzzer. If "
               "other options\n"
               "      fail, poke the Awesome Fuzzing Discord for "
               "troubleshooting tips.\n",
               msg_exit_code);

        }

#undef MSG_ULIMIT_USAGE
#undef MSG_FORK_ON_APPLE

        if (sgf->fsrv.uses_crash_exitcode) {

          WARNF(
              "Test case '%s' results in a crash or SGF_CRASH_EXITCODE %d, "
              "skipping",
              fn, (int)(s8)sgf->fsrv.crash_exitcode);

        } else {

          if (sgf->sgf_env.sgf_crashing_seeds_as_new_crash) {

            WARNF(
                "Test case '%s' results in a crash, "
                "as SGF_CRASHING_SEEDS_AS_NEW_CRASH is set, "
                "saving as a new crash",
                fn);

          } else {

            WARNF("Test case '%s' results in a crash, skipping", fn);

          }

        }

        if (sgf->sgf_env.sgf_exit_on_seed_issues) {

          FATAL("As SGF_EXIT_ON_SEED_ISSUES is set, sgf-fuzz exits.");

        }

        /* Remove from fuzzing queue but keep for splicing */

        if (!q->was_fuzzed) {

          q->was_fuzzed = 1;
          sgf->reinit_table = 1;
          --sgf->pending_not_fuzzed;
          --sgf->active_items;

        }

        /* Crashing seeds will be regarded as new crashes on startup */
        if (sgf->sgf_env.sgf_crashing_seeds_as_new_crash) {

          ++sgf->total_crashes;

          if (likely(!sgf->non_instrumented_mode)) {

            classify_counts(&sgf->fsrv);

            simplify_trace(sgf, sgf->fsrv.trace_bits);

            if (!has_new_bits(sgf, sgf->virgin_crash)) { break; }

          }

          if (unlikely(!sgf->saved_crashes) &&
              (sgf->sgf_env.sgf_no_crash_readme != 1)) {

            write_crash_readme(sgf);

          }

          u8  crash_fn[PATH_MAX];
          u8 *use_name = strstr(q->fname, ",orig:");

          if (!use_name) {

            use_name = strstr(q->fname, ",sync:");
            if (!use_name) { use_name = q->fname + strlen(q->fname); }

          }

          sgf->stage_name = "dry_run";
          sgf->stage_short = "dry_run";

#ifndef SIMPLE_FILES

          if (!sgf->sgf_env.sgf_sha1_filenames) {

            snprintf(
                crash_fn, PATH_MAX, "%s/crashes/id:%06llu,sig:%02u,%s%s%s%s",
                sgf->out_dir, sgf->saved_crashes, sgf->fsrv.last_kill_signal,
                describe_op(
                    sgf, 0,
                    NAME_MAX - strlen("id:000000,sig:00,") - strlen(use_name)),
                use_name, sgf->file_extension ? "." : "",
                sgf->file_extension ? (const char *)sgf->file_extension : "");

          } else {

            const char *hex = sha1_hex(use_mem, read_len);
            snprintf(
                crash_fn, PATH_MAX, "%s/crashes/%s%s%s", sgf->out_dir, hex,
                sgf->file_extension ? "." : "",
                sgf->file_extension ? (const char *)sgf->file_extension : "");
            ck_free((char *)hex);

          }

#else

          snprintf(
              crash_fn, PATH_MAX, "%s/crashes/id_%06llu_%02u%s%s", sgf->out_dir,
              sgf->saved_crashes, sgf->fsrv.last_kill_signal,
              sgf->file_extension ? "." : "",
              sgf->file_extension ? (const char *)sgf->file_extension : "");

#endif

          ++sgf->saved_crashes;

          fd = open(crash_fn, O_WRONLY | O_CREAT | O_EXCL, sgf->perm);
          if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", crash_fn); }
          ck_write(fd, use_mem, read_len, crash_fn);

          if (sgf->chown_needed) {

            if (fchown(fd, -1, sgf->fsrv.gid) == -1) {

              PFATAL("fchown() failed");

            }

          }

          close(fd);

#ifdef __linux__
          if (sgf->fsrv.nyx_mode) {

            u8 crash_log_fn[PATH_MAX];

            snprintf(crash_log_fn, PATH_MAX, "%s.log", crash_fn);
            fd = open(crash_log_fn, O_WRONLY | O_CREAT | O_EXCL, sgf->perm);
            if (unlikely(fd < 0)) {

              PFATAL("Unable to create '%s'", crash_log_fn);

            }

            u32 nyx_aux_string_len = sgf->fsrv.nyx_handlers->nyx_get_aux_string(
                sgf->fsrv.nyx_runner, sgf->fsrv.nyx_aux_string,
                sgf->fsrv.nyx_aux_string_len);

            ck_write(fd, sgf->fsrv.nyx_aux_string, nyx_aux_string_len,
                     crash_log_fn);

            if (sgf->chown_needed) {

              if (fchown(fd, -1, sgf->fsrv.gid) == -1) {

                PFATAL("fchown() failed");

              }

            }

            close(fd);

          }

#endif

          sgf->last_crash_time = get_cur_time();
          sgf->last_crash_execs = sgf->fsrv.total_execs;

        } else {

          u32 i = 0;
          while (unlikely(i < sgf->queued_items && sgf->queue_buf[i] &&
                          sgf->queue_buf[i]->disabled)) {

            ++i;

          }

          if (i < sgf->queued_items && sgf->queue_buf[i]) {

            sgf->queue = sgf->queue_buf[i];

          } else {

            sgf->queue = sgf->queue_buf[0];

          }

          sgf->max_depth = 0;
          for (i = 0; i < sgf->queued_items && likely(sgf->queue_buf[i]); i++) {

            if (!sgf->queue_buf[i]->disabled &&
                sgf->queue_buf[i]->depth > sgf->max_depth)
              sgf->max_depth = sgf->queue_buf[i]->depth;

          }

        }

        q->disabled = 1;
        q->perf_score = 0;

        break;

      case FSRV_RUN_ERROR:

        FATAL("Unable to execute target application ('%s')", sgf->argv[0]);

      case FSRV_RUN_NOINST:
#ifdef __linux__
        if (sgf->fsrv.nyx_mode && sgf->fsrv.nyx_runner != NULL) {

          sgf->fsrv.nyx_handlers->nyx_shutdown(sgf->fsrv.nyx_runner);

        }

#endif
        FATAL("No instrumentation detected");

      case FSRV_RUN_NOBITS:

        ++sgf->useless_at_start;

        if (!sgf->in_bitmap && !sgf->shuffle_queue) {

          WARNF("No new instrumentation output, test case may be useless.");

        }

        break;

    }

    if (unlikely(q->var_behavior && !sgf->sgf_env.sgf_no_warn_instability)) {

      WARNF("Instrumentation output varies across runs.");

    }

    if (!sgf->in_place_resume) {

      if (++idx >= sgf->queued_items) { done = 1; }

    } else {

      if (idx == 0) { done = 1; }

    }

  } while (!done);

  if (cal_failures) {

    if (cal_failures == sgf->queued_items) {

      FATAL("All test cases time out or crash, giving up!");

    }

    WARNF("Skipped %u test cases (%0.02f%%) due to timeouts or crashes.",
          cal_failures, ((double)cal_failures) * 100 / sgf->queued_items);

    if (cal_failures * 5 > sgf->queued_items) {

      WARNF(cLRD "High percentage of rejected test cases, check settings!");

    }

  }

  /* Now we remove all entries from the queue that have a duplicate trace map */

  u32 duplicates = 0, i;

  for (idx = 0; idx < sgf->queued_items - 1; idx++) {

    q = sgf->queue_buf[idx];
    if (!q || q->disabled || q->cal_failed || !q->exec_cksum) { continue; }

    for (i = idx + 1; likely(i < sgf->queued_items && sgf->queue_buf[i]); ++i) {

      struct queue_entry *p = sgf->queue_buf[i];
      if (p->disabled || p->cal_failed || !p->exec_cksum) { continue; }
      if (p->exec_cksum != q->exec_cksum) continue;

      duplicates = 1;

      // we keep the shorter file
      struct queue_entry *to_disable, *to_keep;
      if (p->len >= q->len) {

        to_disable = p;
        to_keep = q;

      } else {

        to_disable = q;
        to_keep = p;

      }

      if (!to_disable->was_fuzzed) {

        to_disable->was_fuzzed = 1;
        sgf->reinit_table = 1;
        --sgf->pending_not_fuzzed;
        --sgf->active_items;

      }

      to_disable->disabled = 1;
      to_disable->perf_score = 0;

      if (sgf->debug) {

        WARNF("Same coverage - %s is kept active, %s is disabled.",
              to_keep->fname, to_disable->fname);

      }

      // end inner loop because outer loop entry is disabled now
      if (to_disable == q) break;

    }

  }

  if (duplicates) {

    sgf->max_depth = 0;

    for (idx = 0; idx < sgf->queued_items; idx++) {

      if (sgf->queue_buf[idx] && !sgf->queue_buf[idx]->disabled &&
          sgf->queue_buf[idx]->depth > sgf->max_depth)
        sgf->max_depth = sgf->queue_buf[idx]->depth;

    }

    sgf->queue_top = sgf->queue;

  }

  OKF("All test cases processed.");

}

/* Helper function: link() if possible, copy otherwise. */

static void link_or_copy(u8 *old_path, u8 *new_path, mode_t perm) {

  s32 i = link(old_path, new_path);
  if (!i) { return; }

  s32 sfd, dfd;
  u8 *tmp;

  sfd = open(old_path, O_RDONLY);
  if (sfd < 0) { PFATAL("Unable to open '%s'", old_path); }

  dfd = open(new_path, O_WRONLY | O_CREAT | O_EXCL, perm);
  if (dfd < 0) { PFATAL("Unable to create '%s'", new_path); }

  tmp = ck_alloc(64 * 1024);

  while ((i = read(sfd, tmp, 64 * 1024)) > 0) {

    ck_write(dfd, tmp, i, new_path);

  }

  if (i < 0) { PFATAL("read() failed"); }

  ck_free(tmp);
  close(sfd);
  close(dfd);

}

/* Create hard links for input test cases in the output directory, choosing
   good names and pivoting accordingly. */

void pivot_inputs(sgf_state_t *sgf) {

  struct queue_entry *q;
  u32                 id = 0, i;

  ACTF("Creating hard links for all input files...");

  for (i = 0; i < sgf->queued_items && likely(sgf->queue_buf[i]); i++) {

    q = sgf->queue_buf[i];

    if (unlikely(q->disabled)) { continue; }

    u8 *nfn, *rsl = strrchr(q->fname, '/');
    u32 orig_id;

    if (!rsl) {

      rsl = q->fname;

    } else {

      ++rsl;

    }

    /* If the original file name conforms to the syntax and the recorded
       ID matches the one we'd assign, just use the original file name.
       This is valuable for resuming fuzzing runs. */

    if (sgf->in_place_resume ||
        (!strncmp(rsl, CASE_PREFIX, 3) &&
         sscanf(rsl + 3, "%06u", &orig_id) == 1 && orig_id == id)) {

      u8 *src_str;
      u32 src_id;

      sgf->resuming_fuzz = 1;
      nfn = alloc_printf(
          "%s/queue/%s%s%s", sgf->out_dir, rsl, sgf->file_extension ? "." : "",
          sgf->file_extension ? (const char *)sgf->file_extension : "");

      /* Since we're at it, let's also get the parent and figure out the
         appropriate depth for this entry. */

      src_str = strchr(rsl + 3, ':');

      if (src_str && sscanf(src_str + 1, "%06u", &src_id) == 1) {

        if (src_id < sgf->queued_items) {

          struct queue_entry *s = sgf->queue_buf[src_id];

          if (s) { q->depth = s->depth + 1; }

        }

        if (sgf->max_depth < q->depth) { sgf->max_depth = q->depth; }

      }

    } else {

      /* No dice - invent a new name, capturing the original one as a
         substring. */

#ifndef SIMPLE_FILES

      u8 *use_name = strstr(rsl, ",orig:");

      if (use_name) {

        use_name += 6;

      } else {

        use_name = rsl;

      }

      if (!sgf->sgf_env.sgf_sha1_filenames) {

        nfn = alloc_printf(
            "%s/queue/id:%06u,time:0,execs:%llu,orig:%s%s%s", sgf->out_dir, id,
            sgf->fsrv.total_execs, use_name, sgf->file_extension ? "." : "",
            sgf->file_extension ? (const char *)sgf->file_extension : "");

      } else {

        const char *hex = sha1_hex_for_file(q->fname, q->len);
        nfn = alloc_printf(
            "%s/queue/%s%s%s", sgf->out_dir, hex,
            sgf->file_extension ? "." : "",
            sgf->file_extension ? (const char *)sgf->file_extension : "");
        ck_free((char *)hex);

      }

      u8 *pos = strrchr(nfn, '/');
      no_spaces(pos + 30);

#else

      nfn = alloc_printf(
          "%s/queue/id_%06u%s%s", sgf->out_dir, id,
          sgf->file_extension ? "." : "",
          sgf->file_extension ? (const char *)sgf->file_extension : "");

#endif                                                    /* ^!SIMPLE_FILES */

    }

    /* Pivot to the new queue entry. */

    link_or_copy(q->fname, nfn, sgf->perm);
    ck_free(q->fname);
    q->fname = nfn;

    if (sgf->chown_needed) {

      if (chown(nfn, -1, sgf->fsrv.gid) == -1) { PFATAL("fchown() failed"); }

    }

    /* Make sure that the passed_det value carries over, too. */

    if (q->passed_det) { mark_as_det_done(sgf, q); }

    if (sgf->custom_mutators_count) {

      run_afl_custom_queue_new_entry(sgf, q, q->fname, NULL);

    }

    ++id;

  }

  if (sgf->in_place_resume) { nuke_resume_dir(sgf); }

}

/* When resuming, try to find the queue position to start from. This makes sense
   only when resuming, and when we can find the original fuzzer_stats. */

u32 find_start_position(sgf_state_t *sgf) {

  u8 tmp[4096] = {0};                    /* Ought to be enough for anybody. */

  u8 *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!sgf->resuming_fuzz) { return 0; }

  if (sgf->in_place_resume) {

    fn = alloc_printf("%s/fuzzer_stats", sgf->out_dir);

  } else {

    fn = alloc_printf("%s/../fuzzer_stats", sgf->in_dir);

  }

  fd = open(fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0) { return 0; }

  i = read(fd, tmp, sizeof(tmp) - 1);
  (void)i;                                                 /* Ignore errors */
  close(fd);

  off = strstr(tmp, "cur_item          : ");
  if (!off) { return 0; }

  ret = atoi(off + 20);
  if (ret >= sgf->queued_items) { ret = 0; }
  return ret;

}

/* The same, but for timeouts. The idea is that when resuming sessions without
   -t given, we don't want to keep auto-scaling the timeout over and over
   again to prevent it from growing due to random flukes. */

void find_timeout(sgf_state_t *sgf) {

  u8 tmp[4096] = {0};                    /* Ought to be enough for anybody. */

  u8 *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!sgf->resuming_fuzz) { return; }

  if (sgf->in_place_resume) {

    fn = alloc_printf("%s/fuzzer_stats", sgf->out_dir);

  } else {

    fn = alloc_printf("%s/../fuzzer_stats", sgf->in_dir);

  }

  fd = open(fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0) { return; }

  i = read(fd, tmp, sizeof(tmp) - 1);
  (void)i;                                                 /* Ignore errors */
  close(fd);

  off = strstr(tmp, "exec_timeout      : ");
  if (!off) { return; }

  ret = atoi(off + 20);
  if (ret <= 4) { return; }

  sgf->fsrv.exec_tmout = ret;
  sgf->timeout_given = 3;

}

/* A helper function for handle_existing_out_dir(), deleting all prefixed
   files in a directory. */

static u8 delete_files(u8 *path, u8 *prefix) {

  DIR           *d;
  struct dirent *d_ent;

  d = opendir(path);

  if (!d) { return 0; }

  while ((d_ent = readdir(d))) {

    if ((d_ent->d_name[0] != '.' &&
         (!prefix || !strncmp(d_ent->d_name, prefix, strlen(prefix))))
        /* heiko: don't forget the SHA1 files */
        || strspn(d_ent->d_name, "0123456789abcdef") ==
               2 * 20                           /* TODO use 2 * HASH_LENGTH */
    ) {

      u8 *fname = alloc_printf("%s/%s", path, d_ent->d_name);
      if (unlink(fname)) { PFATAL("Unable to delete '%s'", fname); }
      ck_free(fname);

    }

  }

  closedir(d);

  return !!rmdir(path);

}

/* Get the number of runnable processes, with some simple smoothing. */

double get_runnable_processes(void) {

  double res = 0;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__)

  /* I don't see any portable sysctl or so that would quickly give us the
     number of runnable processes; the 1-minute load average can be a
     semi-decent approximation, though. */

  if (getloadavg(&res, 1) != 1) return 0;

#else

  /* On Linux, /proc/stat is probably the best way; load averages are
     computed in funny ways and sometimes don't reflect extremely short-lived
     processes well. */

  FILE *f = fopen("/proc/stat", "r");
  u8    tmp[1024];
  u32   val = 0;

  if (!f) { return 0; }

  while (fgets(tmp, sizeof(tmp), f)) {

    if (!strncmp(tmp, "procs_running ", 14) ||
        !strncmp(tmp, "procs_blocked ", 14)) {

      val += atoi(tmp + 14);

    }

  }

  fclose(f);

  if (!res) {

    res = val;

  } else {

    res = res * (1.0 - 1.0 / AVG_SMOOTHING) +
          ((double)val) * (1.0 / AVG_SMOOTHING);

  }

#endif          /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__ || __NetBSD__) */

  return res;

}

/* Delete the temporary directory used for in-place session resume. */

void nuke_resume_dir(sgf_state_t *sgf) {

  u8 *const case_prefix = sgf->sgf_env.sgf_sha1_filenames ? "" : CASE_PREFIX;
  u8       *fn;

  fn = alloc_printf("%s/_resume/.state/deterministic_done", sgf->out_dir);
  if (delete_files(fn, case_prefix)) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/auto_extras", sgf->out_dir);
  if (delete_files(fn, "auto_")) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/redundant_edges", sgf->out_dir);
  if (delete_files(fn, case_prefix)) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/variable_behavior", sgf->out_dir);
  if (delete_files(fn, case_prefix)) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state", sgf->out_dir);
  if (rmdir(fn) && errno != ENOENT) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/_resume", sgf->out_dir);
  if (delete_files(fn, case_prefix)) { goto dir_cleanup_failed; }
  ck_free(fn);

  return;

dir_cleanup_failed:

  FATAL("_resume directory cleanup failed");

}

/* Delete fuzzer output directory if we recognize it as ours, if the fuzzer
   is not currently running, and if the last run time isn't too great.
   Resume fuzzing if `-` is set as in_dir or if SGF_AUTORESUME is set */

static void handle_existing_out_dir(sgf_state_t *sgf) {

  u8 *const case_prefix = sgf->sgf_env.sgf_sha1_filenames ? "" : CASE_PREFIX;
  FILE     *f;
  u8       *fn = alloc_printf("%s/fuzzer_stats", sgf->out_dir);

  /* See if the output directory is locked. If yes, bail out. If not,
     create a lock that will persist for the lifetime of the process
     (this requires leaving the descriptor open).*/

  sgf->fsrv.out_dir_fd = open(sgf->out_dir, O_RDONLY);
  if (sgf->fsrv.out_dir_fd < 0) { PFATAL("Unable to open '%s'", sgf->out_dir); }

#ifndef __sun

  if (flock(sgf->fsrv.out_dir_fd, LOCK_EX | LOCK_NB) && errno == EWOULDBLOCK) {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like the job output directory is being actively used by "
         "another\n"
         "    instance of sgf-fuzz. You will need to choose a different %s\n"
         "    or stop the other process first.\n",
         sgf->sync_id ? "fuzzer ID" : "output location");

    FATAL("Directory '%s' is in use", sgf->out_dir);

  }

#endif                                                            /* !__sun */

  f = fopen(fn, "r");

  if (f) {

    u64 start_time2, last_update;

    if (fscanf(f,
               "start_time     : %llu\n"
               "last_update    : %llu\n",
               &start_time2, &last_update) != 2) {

      FATAL("Malformed data in '%s'", fn);

    }

    fclose(f);

    /* Autoresume treats a normal run as in_place_resume if a valid out dir
     * already exists */

    if (!sgf->in_place_resume && sgf->autoresume) {

      OKF("Detected prior run with SGF_AUTORESUME set. Resuming.");
      sgf->in_place_resume = 1;

    }

    /* Let's see how much work is at stake. */

    if (!sgf->in_place_resume && last_update > start_time2 &&
        last_update - start_time2 > OUTPUT_GRACE * 60) {

      SAYF("\n" cLRD "[-] " cRST
           "The job output directory already exists and contains the results "
           "of more\n"
           "    than %d minutes worth of fuzzing. To avoid data loss, sgf-fuzz "
           "will *NOT*\n"
           "    automatically delete this data for you.\n\n"

           "    If you wish to start a new session, remove or rename the "
           "directory manually,\n"
           "    or specify a different output location for this job. To resume "
           "the old\n"
           "    session, pass '-' as input directory in the command line ('-i "
           "-')\n"
           "    or set the 'SGF_AUTORESUME=1' env variable and try again.\n",
           OUTPUT_GRACE);

      FATAL("At-risk data found in '%s'", sgf->out_dir);

    }

  }

  ck_free(fn);

  /* The idea for in-place resume is pretty simple: we temporarily move the old
     queue/ to a new location that gets deleted once import to the new queue/
     is finished. If _resume/ already exists, the current queue/ may be
     incomplete due to an earlier abort, so we want to use the old _resume/
     dir instead, and we let rename() fail silently. */

  if (sgf->in_place_resume) {

    u8 *orig_q = alloc_printf("%s/queue", sgf->out_dir);

    sgf->in_dir = alloc_printf("%s/_resume", sgf->out_dir);

    rename(orig_q, sgf->in_dir);                           /* Ignore errors */

    OKF("Output directory exists, will attempt session resume.");

    ck_free(orig_q);

  } else {

    OKF("Output directory exists but deemed OK to reuse.");

  }

  ACTF("Deleting old session data...");

  /* Okay, let's get the ball rolling! First, we need to get rid of the entries
     in <sgf->out_dir>/.synced/.../id:*, if any are present. */

  if (!sgf->in_place_resume) {

    fn = alloc_printf("%s/.synced", sgf->out_dir);
    if (delete_files(fn, NULL)) { goto dir_cleanup_failed; }
    ck_free(fn);

  }

  /* Next, we need to clean up <sgf->out_dir>/queue/.state/ subdirectories: */

  fn = alloc_printf("%s/queue/.state/deterministic_done", sgf->out_dir);
  if (delete_files(fn, case_prefix)) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/auto_extras", sgf->out_dir);
  if (delete_files(fn, "auto_")) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/redundant_edges", sgf->out_dir);
  if (delete_files(fn, case_prefix)) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/variable_behavior", sgf->out_dir);
  if (delete_files(fn, case_prefix)) { goto dir_cleanup_failed; }
  ck_free(fn);

  /* Then, get rid of the .state subdirectory itself (should be empty by now)
     and everything matching <sgf->out_dir>/queue/id:*. */

  fn = alloc_printf("%s/queue/.state", sgf->out_dir);
  if (rmdir(fn) && errno != ENOENT) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/queue", sgf->out_dir);
  if (delete_files(fn, case_prefix)) { goto dir_cleanup_failed; }
  ck_free(fn);

  /* All right, let's do <sgf->out_dir>/crashes/id:* and
   * <sgf->out_dir>/hangs/id:*. */

  if (!sgf->in_place_resume) {

    fn = alloc_printf("%s/crashes/README.txt", sgf->out_dir);
    unlink(fn);                                            /* Ignore errors */
    ck_free(fn);

  }

  fn = alloc_printf("%s/crashes", sgf->out_dir);

  /* Make backup of the crashes directory if it's not empty and if we're
     doing in-place resume. */

  if (sgf->in_place_resume && rmdir(fn)) {

    time_t    cur_t = time(0);
    struct tm t;
    localtime_r(&cur_t, &t);

#ifndef SIMPLE_FILES

    u8 *nfn =
        alloc_printf("%s.%04d-%02d-%02d-%02d:%02d:%02d", fn, t.tm_year + 1900,
                     t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);

#else

    u8 *nfn =
        alloc_printf("%s_%04d%02d%02d%02d%02d%02d", fn, t.tm_year + 1900,
                     t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);

#endif                                                    /* ^!SIMPLE_FILES */

    rename(fn, nfn);                                      /* Ignore errors. */
    ck_free(nfn);

  }

#ifdef SGF_PERSISTENT_RECORD
  delete_files(fn, RECORD_PREFIX);
#endif
  if (delete_files(fn, case_prefix)) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/hangs", sgf->out_dir);

  /* Backup hangs, too. */

  if (sgf->in_place_resume && rmdir(fn)) {

    time_t    cur_t = time(0);
    struct tm t;
    localtime_r(&cur_t, &t);

#ifndef SIMPLE_FILES

    u8 *nfn =
        alloc_printf("%s.%04d-%02d-%02d-%02d:%02d:%02d", fn, t.tm_year + 1900,
                     t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);

#else

    u8 *nfn =
        alloc_printf("%s_%04d%02d%02d%02d%02d%02d", fn, t.tm_year + 1900,
                     t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);

#endif                                                    /* ^!SIMPLE_FILES */

    rename(fn, nfn);                                      /* Ignore errors. */
    ck_free(nfn);

  }

  #ifdef SGF_PERSISTENT_RECORD
  delete_files(fn, RECORD_PREFIX);
  #endif
  if (delete_files(fn, case_prefix)) { goto dir_cleanup_failed; }
  ck_free(fn);

  if (sgf->check_data_race) {

    fn = alloc_printf("%s/races", sgf->out_dir);

    if (sgf->in_place_resume && rmdir(fn)) {

      time_t    cur_t = time(0);
      struct tm t;
      localtime_r(&cur_t, &t);

#ifndef SIMPLE_FILES

      u8 *nfn =
          alloc_printf("%s.%04d-%02d-%02d-%02d:%02d:%02d", fn,
                       t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour,
                       t.tm_min, t.tm_sec);

#else

      u8 *nfn =
          alloc_printf("%s_%04d%02d%02d%02d%02d%02d", fn, t.tm_year + 1900,
                       t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min,
                       t.tm_sec);

#endif                                                    /* ^!SIMPLE_FILES */

      rename(fn, nfn);                                    /* Ignore errors. */
      ck_free(nfn);

    }

    if (delete_files(fn, case_prefix)) { goto dir_cleanup_failed; }
    ck_free(fn);

  }

  /* Handle IJON max directory - preserve during resume, clean during overwrite
   */
  fn = alloc_printf("%s/ijon_max", sgf->out_dir);

  if (sgf->in_place_resume) {

    /* During resume: preserve IJON directory by renaming (like crashes/hangs)
     */
    time_t    cur_t = time(0);
    struct tm t;
    localtime_r(&cur_t, &t);

#ifndef SIMPLE_FILES
    u8 *nfn =
        alloc_printf("%s.%04d-%02d-%02d-%02d:%02d:%02d", fn, t.tm_year + 1900,
                     t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
#else
    u8 *nfn =
        alloc_printf("%s_%04d%02d%02d%02d%02d%02d", fn, t.tm_year + 1900,
                     t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
#endif
    rename(fn, nfn);                /* Ignore errors like other directories */
    ck_free(nfn);

  } else {

    /* During overwrite: clean up IJON files */
    delete_files(fn,
                 NULL); /* Ignore errors - handles non-existence gracefully */

  }

  ck_free(fn);

  /* And now, for some finishing touches. */

  if (sgf->file_extension) {

    fn = alloc_printf("%s/.cur_input.%s", sgf->out_dir, sgf->file_extension);

  } else {

    fn = alloc_printf("%s/.cur_input", sgf->out_dir);

  }

  if (unlink(fn) && errno != ENOENT) { goto dir_cleanup_failed; }
  ck_free(fn);

  if (sgf->sgf_env.sgf_tmpdir) {

    if (sgf->file_extension) {

      fn = alloc_printf("%s/.cur_input.%s", sgf->sgf_env.sgf_tmpdir,
                        sgf->file_extension);

    } else {

      fn = alloc_printf("%s/.cur_input", sgf->sgf_env.sgf_tmpdir);

    }

    if (unlink(fn) && errno != ENOENT) { goto dir_cleanup_failed; }
    ck_free(fn);

  }

  fn = alloc_printf("%s/fuzz_bitmap", sgf->out_dir);
  if (unlink(fn) && errno != ENOENT) { goto dir_cleanup_failed; }
  ck_free(fn);

  if (!sgf->in_place_resume) {

    fn = alloc_printf("%s/fuzzer_stats", sgf->out_dir);
    if (unlink(fn) && errno != ENOENT) { goto dir_cleanup_failed; }
    ck_free(fn);

  }

  if (!sgf->in_place_resume) {

    fn = alloc_printf("%s/plot_data", sgf->out_dir);
    if (unlink(fn) && errno != ENOENT) { goto dir_cleanup_failed; }
    ck_free(fn);

  }

  fn = alloc_printf("%s/queue_data", sgf->out_dir);
  if (unlink(fn) && errno != ENOENT) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/cmdline", sgf->out_dir);
  if (unlink(fn) && errno != ENOENT) { goto dir_cleanup_failed; }
  ck_free(fn);

  OKF("Output dir cleanup successful.");

  /* Wow... is that all? If yes, celebrate! */

  return;

dir_cleanup_failed:

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, the fuzzer tried to reuse your output directory, but bumped "
       "into\n"
       "    some files that shouldn't be there or that couldn't be removed - "
       "so it\n"
       "    decided to abort! This happened while processing this path:\n\n"

       "    %s\n\n"
       "    Please examine and manually delete the files, or specify a "
       "different\n"
       "    output location for the tool.\n",
       fn);
  FATAL("Output directory cleanup failed");

}

/* If this is a -S secondary node, ensure a -M main node is running,
  if a main node is running when another main is started, then warn */

int check_main_node_exists(sgf_state_t *sgf) {

  DIR           *sd;
  struct dirent *sd_ent;
  u8            *fn;

  sd = opendir(sgf->sync_dir);
  if (!sd) { return 0; }

  while ((sd_ent = readdir(sd))) {

    /* Skip dot files and our own output directory. */

    if (sd_ent->d_name[0] == '.' || !strcmp(sgf->sync_id, sd_ent->d_name)) {

      continue;

    }

    fn = alloc_printf("%s/%s/is_main_node", sgf->sync_dir, sd_ent->d_name);
    int res = access(fn, F_OK);
    free(fn);
    if (res == 0) {

      closedir(sd);
      return 1;

    }

  }

  closedir(sd);

  return 0;

}

/* Prepare output directories and fds. */

void setup_dirs_fds(sgf_state_t *sgf) {

  u8 *tmp;

  ACTF("Setting up output directories...");

  if (sgf->sync_id && mkdir(sgf->sync_dir, sgf->dir_perm) && errno != EEXIST) {

    PFATAL("Unable to create '%s'", sgf->sync_dir);

  }

  if (mkdir(sgf->out_dir, sgf->dir_perm)) {

    if (errno != EEXIST) { PFATAL("Unable to create '%s'", sgf->out_dir); }

    handle_existing_out_dir(sgf);

  } else {

    if (sgf->chown_needed) {

      if (chown(sgf->out_dir, -1, sgf->fsrv.gid) == -1) {

        PFATAL("fchown() failed");

      }

    }

    if (sgf->in_place_resume) {

      FATAL("Resume attempted but old output directory not found");

    }

    sgf->fsrv.out_dir_fd = open(sgf->out_dir, O_RDONLY);

#ifndef __sun

    if (sgf->fsrv.out_dir_fd < 0 ||
        flock(sgf->fsrv.out_dir_fd, LOCK_EX | LOCK_NB)) {

      PFATAL("Unable to flock() output directory.");

    }

#endif                                                            /* !__sun */

  }

  if (sgf->is_main_node) {

    u8 *x = alloc_printf("%s/is_main_node", sgf->out_dir);
    int fd = open(x, O_CREAT | O_RDWR, 0644);
    if (fd < 0) FATAL("cannot create %s", x);
    free(x);
    close(fd);

  }

  /* Queue directory for any starting & discovered paths. */

  tmp = alloc_printf("%s/queue", sgf->out_dir);
  if (mkdir(tmp, sgf->dir_perm)) { PFATAL("Unable to create '%s'", tmp); }
  ck_free(tmp);

  /* Top-level directory for queue metadata used for session
     resume and related tasks. */

  tmp = alloc_printf("%s/queue/.state/", sgf->out_dir);
  if (mkdir(tmp, sgf->dir_perm)) { PFATAL("Unable to create '%s'", tmp); }
  ck_free(tmp);

  /* Directory for flagging queue entries that went through
     deterministic fuzzing in the past. */

  tmp = alloc_printf("%s/queue/.state/deterministic_done/", sgf->out_dir);
  if (mkdir(tmp, sgf->dir_perm)) { PFATAL("Unable to create '%s'", tmp); }
  ck_free(tmp);

  /* Directory with the auto-selected dictionary entries. */

  tmp = alloc_printf("%s/queue/.state/auto_extras/", sgf->out_dir);
  if (mkdir(tmp, sgf->dir_perm)) { PFATAL("Unable to create '%s'", tmp); }
  ck_free(tmp);

  /* Sync directory for keeping track of cooperating fuzzers. */

  if (sgf->sync_id) {

    tmp = alloc_printf("%s/.synced/", sgf->out_dir);

    if (mkdir(tmp, sgf->dir_perm) &&
        (!sgf->in_place_resume || errno != EEXIST)) {

      PFATAL("Unable to create '%s'", tmp);

    }

    ck_free(tmp);

  }

  /* All recorded crashes. */

  tmp = alloc_printf("%s/crashes", sgf->out_dir);
  if (mkdir(tmp, sgf->dir_perm)) { PFATAL("Unable to create '%s'", tmp); }
  ck_free(tmp);

  /* All recorded hangs. */

  tmp = alloc_printf("%s/hangs", sgf->out_dir);
  if (mkdir(tmp, sgf->dir_perm)) { PFATAL("Unable to create '%s'", tmp); }
  ck_free(tmp);

  if (sgf->check_data_race) {

    tmp = alloc_printf("%s/races", sgf->out_dir);
    if (mkdir(tmp, sgf->dir_perm)) { PFATAL("Unable to create '%s'", tmp); }
    ck_free(tmp);

  }

  /* Generally useful file descriptors. */

  sgf->fsrv.dev_null_fd = open("/dev/null", O_RDWR);
  if (sgf->fsrv.dev_null_fd < 0) { PFATAL("Unable to open /dev/null"); }

  sgf->fsrv.dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (sgf->fsrv.dev_urandom_fd < 0) { PFATAL("Unable to open /dev/urandom"); }

  /* Gnuplot output file. */

  tmp = alloc_printf("%s/plot_data", sgf->out_dir);

  if (!sgf->in_place_resume) {

    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, sgf->perm);
    if (fd < 0) { PFATAL("Unable to create '%s'", tmp); }
    if (sgf->chown_needed) {

      if (fchown(fd, -1, sgf->fsrv.gid) == -1) { PFATAL("fchown() failed"); }

    }

    ck_free(tmp);

    sgf->fsrv.plot_file = fdopen(fd, "w");
    if (!sgf->fsrv.plot_file) { PFATAL("fdopen() failed"); }

    fprintf(sgf->fsrv.plot_file,
            "relative_time, cycles_done, cur_item, corpus_count, "
            "pending_total, pending_favs, map_size, saved_crashes, "
            "saved_hangs, max_depth, execs_per_sec, total_execs, edges_found, "
            "total_crashes, servers_count, mo_coverage, rf_coverage");

    if (sgf->san_binary_length) {

      for (u8 i = 0; i < sgf->san_binary_length; i++) {

        fprintf(sgf->fsrv.plot_file, ", sand_fsrv%u_exec", i);

      }

    }

    fprintf(sgf->fsrv.plot_file, "\n");

  } else {

    int fd = open(tmp, O_WRONLY | O_CREAT, sgf->perm);
    if (fd < 0) { PFATAL("Unable to create '%s'", tmp); }
    if (sgf->chown_needed) {

      if (fchown(fd, -1, sgf->fsrv.gid) == -1) { PFATAL("fchown() failed"); }

    }

    ck_free(tmp);

    sgf->fsrv.plot_file = fdopen(fd, "w");
    if (!sgf->fsrv.plot_file) { PFATAL("fdopen() failed"); }

    fseek(sgf->fsrv.plot_file, 0, SEEK_END);

  }

  fflush(sgf->fsrv.plot_file);

#ifdef INTROSPECTION

  tmp = alloc_printf("%s/plot_det_data", sgf->out_dir);

  int fd = open(tmp, O_WRONLY | O_CREAT, sgf->perm);
  if (fd < 0) { PFATAL("Unable to create '%s'", tmp); }
  if (sgf->chown_needed) {

    if (fchown(fd, -1, sgf->fsrv.gid) == -1) { PFATAL("fchown() failed"); }

  }

  ck_free(tmp);

  sgf->fsrv.det_plot_file = fdopen(fd, "w");
  if (!sgf->fsrv.det_plot_file) { PFATAL("fdopen() failed"); }

  if (sgf->in_place_resume) { fseek(sgf->fsrv.det_plot_file, 0, SEEK_END); }

#endif

  /* ignore errors */

}

void setup_cmdline_file(sgf_state_t *sgf, char **argv) {

  u8 *tmp;
  s32 fd;
  u32 i = 0;

  FILE *cmdline_file = NULL;

  /* Store the command line to reproduce our findings */
  tmp = alloc_printf("%s/cmdline", sgf->out_dir);
  fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, sgf->perm);
  if (fd < 0) { PFATAL("Unable to create '%s'", tmp); }
  if (sgf->chown_needed) {

    if (fchown(fd, -1, sgf->fsrv.gid) == -1) { PFATAL("fchown() failed"); }

  }

  ck_free(tmp);

  cmdline_file = fdopen(fd, "w");
  if (!cmdline_file) { PFATAL("fdopen() failed"); }

  while (argv[i]) {

    fprintf(cmdline_file, "%s\n", argv[i]);
    ++i;

  }

  fclose(cmdline_file);

}

/* Setup the output file for fuzzed data, if not using -f. */

void setup_stdio_file(sgf_state_t *sgf) {

  if (sgf->file_extension) {

    sgf->fsrv.out_file =
        alloc_printf("%s/.cur_input.%s", sgf->tmp_dir, sgf->file_extension);

  } else {

    sgf->fsrv.out_file = alloc_printf("%s/.cur_input", sgf->tmp_dir);

  }

  unlink(sgf->fsrv.out_file);                              /* Ignore errors */

  sgf->fsrv.out_fd =
      open(sgf->fsrv.out_file, O_RDWR | O_CREAT | O_EXCL, sgf->perm);

  if (sgf->fsrv.out_fd < 0) {

    PFATAL("Unable to create '%s'", sgf->fsrv.out_file);

  }

  if (sgf->chown_needed) {

    if (fchown(sgf->fsrv.out_fd, -1, sgf->fsrv.gid) == -1) {

      PFATAL("fchown() failed");

    }

  }

}

/* Make sure that core dumps don't go to a program. */

void check_crash_handling(void) {

#ifdef __APPLE__

  /* Yuck! There appears to be no simple C API to query for the state of
     loaded daemons on MacOS X, and I'm a bit hesitant to do something
     more sophisticated, such as disabling crash reporting via Mach ports,
     until I get a box to test the code. So, for now, we check for crash
     reporting the awful way. */

  #if !TARGET_OS_IPHONE
  if (system("launchctl list 2>/dev/null | grep -q '\\.ReportCrash\\>'"))
    return;

  SAYF(
      "\n" cLRD "[-] " cRST
      "Whoops, your system is configured to forward crash notifications to an\n"
      "    external crash reporting utility. This will cause issues due to "
      "the\n"
      "    extended delay between the fuzzed binary malfunctioning and this "
      "fact\n"
      "    being relayed to the fuzzer via the standard waitpid() API.\n\n"
      "    To avoid having crashes misinterpreted as timeouts, please run the\n"
      "    following commands:\n\n"

      "    SL=/System/Library; PL=com.apple.ReportCrash\n"
      "    launchctl unload -w ${SL}/LaunchAgents/${PL}.plist\n"
      "    sudo launchctl unload -w ${SL}/LaunchDaemons/${PL}.Root.plist\n");

  #endif
  if (!get_afl_env("SGF_I_DONT_CARE_ABOUT_MISSING_CRASHES"))
    FATAL("Crash reporter detected");

#else

  /* This is Linux specific, but I don't think there's anything equivalent on
   *BSD, so we can just let it slide for now. */

  s32 fd = open("/proc/sys/kernel/core_pattern", O_RDONLY);
  u8  fchar;

  if (fd < 0) { return; }

  ACTF("Checking core_pattern...");

  if (read(fd, &fchar, 1) == 1 && fchar == '|') {

    SAYF("\n" cLRD "[-] " cRST
         "Your system is configured to send core dump notifications to an\n"
         "    external utility. This will cause issues: there will be an "
         "extended delay\n"
         "    between stumbling upon a crash and having this information "
         "relayed to the\n"
         "    fuzzer via the standard waitpid() API.\n"
         "    If you're just experimenting, set "
         "'SGF_I_DONT_CARE_ABOUT_MISSING_CRASHES=1'.\n\n"

         "    To avoid having crashes misinterpreted as timeouts, please \n"
         "    temporarily modify /proc/sys/kernel/core_pattern, like so:\n\n"

         "    echo core | sudo tee /proc/sys/kernel/core_pattern\n");

    if (!getenv("SGF_I_DONT_CARE_ABOUT_MISSING_CRASHES")) {

      FATAL("Pipe at the beginning of 'core_pattern'");

    }

  }

  close(fd);

#endif                                                        /* ^__APPLE__ */

}

/* Check CPU governor. */

void check_cpu_governor(sgf_state_t *sgf) {

#ifdef __linux__
  FILE *f;
  u8    tmp[128];
  u64   min = 0, max = 0;

  if (sgf->sgf_env.sgf_skip_cpufreq) { return; }

  if (sgf->cpu_aff > 0) {

    snprintf(tmp, sizeof(tmp), "%s%d%s", "/sys/devices/system/cpu/cpu",
             sgf->cpu_aff, "/cpufreq/scaling_governor");

  } else {

    snprintf(tmp, sizeof(tmp), "%s",
             "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor");

  }

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "r");
  if (!f) {

    if (sgf->cpu_aff > 0) {

      snprintf(tmp, sizeof(tmp), "%s%d%s",
               "/sys/devices/system/cpu/cpufreq/policy", sgf->cpu_aff,
               "/scaling_governor");

    } else {

      snprintf(tmp, sizeof(tmp), "%s",
               "/sys/devices/system/cpu/cpufreq/policy0/scaling_governor");

    }

    f = fopen(tmp, "r");

  }

  if (!f) {

    WARNF("Could not check CPU scaling governor");
    return;

  }

  ACTF("Checking CPU scaling governor...");

  if (!fgets(tmp, 128, f)) { PFATAL("fgets() failed"); }

  fclose(f);

  if (!strncmp(tmp, "perf", 4)) { return; }

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq", "r");

  if (f) {

    if (fscanf(f, "%llu", &min) != 1) { min = 0; }
    fclose(f);

  }

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", "r");

  if (f) {

    if (fscanf(f, "%llu", &max) != 1) { max = 0; }
    fclose(f);

  }

  if (min == max) { return; }

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, your system uses on-demand CPU frequency scaling, adjusted\n"
       "    between %llu and %llu MHz. Unfortunately, the scaling algorithm in "
       "the\n"
       "    kernel is imperfect and can miss the short-lived processes spawned "
       "by\n"
       "    sgf-fuzz. To keep things moving, run these commands as root:\n\n"

       "    cd /sys/devices/system/cpu\n"
       "    echo performance | sudo tee cpu*/cpufreq/scaling_governor\n\n"

       "    You can later go back to the original state by replacing "
       "'performance'\n"
       "    with 'ondemand' or 'powersave'. If you don't want to change the "
       "settings,\n"
       "    set SGF_SKIP_CPUFREQ to make sgf-fuzz skip this check - but expect "
       "some\n"
       "    performance drop.\n",
       min / 1024, max / 1024);
  FATAL("Suboptimal CPU scaling governor");

#elif defined __APPLE__
  u64    min = 0, max = 0;
  size_t mlen = sizeof(min);
  if (sgf->sgf_env.sgf_skip_cpufreq) return;

  ACTF("Checking CPU scaling governor...");

  if (sysctlbyname("hw.cpufrequency_min", &min, &mlen, NULL, 0) == -1) {

    WARNF("Could not check CPU min frequency");
    return;

  }

  if (sysctlbyname("hw.cpufrequency_max", &max, &mlen, NULL, 0) == -1) {

    WARNF("Could not check CPU max frequency");
    return;

  }

  if (min == max) return;

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, your system uses on-demand CPU frequency scaling, adjusted\n"
       "    between %llu and %llu MHz.\n"
       "    If you don't want to check those settings, set "
       "SGF_SKIP_CPUFREQ\n"
       "    to make sgf-fuzz skip this check - but expect some performance "
       "drop.\n",
       min / 1024, max / 1024);
  FATAL("Suboptimal CPU scaling governor");
#else
  (void)sgf;
#endif

}

/* Count the number of logical CPU cores. */

void get_core_count(sgf_state_t *sgf) {

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__DragonFly__)

  size_t s = sizeof(sgf->cpu_core_count);

  /* On *BSD systems, we can just use a sysctl to get the number of CPUs. */

  #ifdef __APPLE__

  if (sysctlbyname("hw.logicalcpu", &sgf->cpu_core_count, &s, NULL, 0) < 0)
    return;

  #else

  int s_name[2] = {CTL_HW, HW_NCPU};

  if (sysctl(s_name, 2, &sgf->cpu_core_count, &s, NULL, 0) < 0) return;

  #endif                                                      /* ^__APPLE__ */

#else

  #ifdef HAVE_AFFINITY

  sgf->cpu_core_count = sysconf(_SC_NPROCESSORS_ONLN);

  #else

  FILE *f = fopen("/proc/stat", "r");
  u8    tmp[1024];

  if (!f) return;

  while (fgets(tmp, sizeof(tmp), f))
    if (!strncmp(tmp, "cpu", 3) && isdigit(tmp[3])) ++sgf->cpu_core_count;

  fclose(f);

  #endif                                                  /* ^HAVE_AFFINITY */

#endif                        /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  if (sgf->cpu_core_count > 0) {

    u32 cur_runnable = 0;

    cur_runnable = (u32)get_runnable_processes();

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__DragonFly__)

    /* Add ourselves, since the 1-minute average doesn't include that yet. */

    ++cur_runnable;

#endif                           /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

    OKF("You have %d CPU core%s and %u runnable tasks (utilization: %0.0f%%).",
        sgf->cpu_core_count, sgf->cpu_core_count > 1 ? "s" : "", cur_runnable,
        cur_runnable * 100.0 / sgf->cpu_core_count);

    if (sgf->cpu_core_count > 1) {

      if (cur_runnable > sgf->cpu_core_count * 1.5) {

        WARNF("System under apparent load, performance may be spotty.");

      } else if ((s64)cur_runnable + 1 <= (s64)sgf->cpu_core_count) {

        OKF("Try parallel jobs - see "
            "%s/fuzzing_in_depth.md#c-using-multiple-cores",
            doc_path);

      }

    }

  } else {

    sgf->cpu_core_count = 0;
    WARNF("Unable to figure out the number of CPU cores.");

  }

}

/* Validate and fix up sgf->out_dir and sync_dir when using -S. */

void fix_up_sync(sgf_state_t *sgf) {

  u8 *x = sgf->sync_id;

  while (*x) {

    if (!isalnum(*x) && *x != '_' && *x != '-') {

      FATAL("Non-alphanumeric fuzzer ID specified via -S or -M");

    }

    ++x;

  }

  if (strlen(sgf->sync_id) > SYNC_ID_MAX_LEN) {

    FATAL("sync_id max length is %d characters", SYNC_ID_MAX_LEN);

  }

  x = alloc_printf("%s/%s", sgf->out_dir, sgf->sync_id);

#ifdef __linux__
  if (sgf->fsrv.nyx_mode) { sgf->fsrv.out_dir_path = sgf->out_dir; }
#endif
  sgf->sync_dir = sgf->out_dir;
  sgf->out_dir = x;

}

/* Handle screen resize (SIGWINCH). */

static void handle_resize(int sig) {

  (void)sig;
  afl_states_clear_screen();

}

/* Check ASAN options. */

void check_asan_opts(sgf_state_t *sgf) {

  u8 *x = get_afl_env("ASAN_OPTIONS");

  (void)(sgf);

  if (x) {

    if (!strstr(x, "abort_on_error=1")) {

      FATAL("Custom ASAN_OPTIONS set without abort_on_error=1 - please fix!");

    }

#ifndef ASAN_BUILD
    if (!sgf->debug && !strstr(x, "symbolize=0")) {

      FATAL("Custom ASAN_OPTIONS set without symbolize=0 - please fix!");

    }

#endif

  }

  x = get_afl_env("MSAN_OPTIONS");

  if (x) {

    if (!strstr(x, "exit_code=" STRINGIFY(MSAN_ERROR))) {

      FATAL("Custom MSAN_OPTIONS set without exit_code=" STRINGIFY(
          MSAN_ERROR) " - please fix!");

    }

    if (!sgf->debug && !strstr(x, "symbolize=0")) {

      FATAL("Custom MSAN_OPTIONS set without symbolize=0 - please fix!");

    }

  }

  x = get_afl_env("LSAN_OPTIONS");

  if (x) {

    if (!strstr(x, "symbolize=0")) {

      FATAL("Custom LSAN_OPTIONS set without symbolize=0 - please fix!");

    }

  }

}

/* Handle stop signal (Ctrl-C, etc). */

static void handle_stop_sig(int sig) {

  (void)sig;
  afl_states_stop();

}

/* Handle skip request (SIGUSR1). */

static void handle_skipreq(int sig) {

  (void)sig;
  afl_states_request_skip();

}

/* Setup shared map for fuzzing with input via sharedmem */

void setup_testcase_shmem(sgf_state_t *sgf) {

  sgf->shm_fuzz = ck_alloc(sizeof(sharedmem_t));

  // we need to set the non-instrumented mode to not overwrite the SHM_ENV_VAR
  size_t shm_fuzz_map_size = SHM_FUZZ_MAP_SIZE_DEFAULT;
  u8    *map = afl_shm_init(sgf->shm_fuzz, shm_fuzz_map_size, 1, sgf->perm,
                         sgf->chown_needed ? sgf->fsrv.gid : -1);
  sgf->shm_fuzz->shmemfuzz_mode = 1;

  if (!map) { FATAL("BUG: Zero return from afl_shm_init."); }

  u8 *shm_fuzz_map_size_str = alloc_printf("%zu", shm_fuzz_map_size);
  setenv(SHM_FUZZ_MAP_SIZE_ENV_VAR, shm_fuzz_map_size_str, 1);
  ck_free(shm_fuzz_map_size_str);

#ifdef USEMMAP
  setenv(SHM_FUZZ_ENV_VAR, sgf->shm_fuzz->g_shm_file_path, 1);
#else
  u8 *shm_str = alloc_printf("%d", sgf->shm_fuzz->shm_id);
  setenv(SHM_FUZZ_ENV_VAR, shm_str, 1);
  ck_free(shm_str);
#endif
  sgf->fsrv.support_shmem_fuzz = 1;
  sgf->fsrv.shmem_fuzz_len = (u32 *)map;
  sgf->fsrv.shmem_fuzz = map + sizeof(u32);

}

/* Do a PATH search and find target binary to see that it exists and
   isn't a shell script - a common and painful mistake. We also check for
   a valid ELF header and for evidence of AFL instrumentation. */

void check_binary(sgf_state_t *sgf, u8 *fname) {

  if (unlikely(!fname)) { FATAL("BUG: Binary name is NULL"); }

  u8         *env_path = 0;
  struct stat st;

  s32 fd;
  u8 *f_data;
  u32 f_len = 0;

  ACTF("Validating target binary...");

  if (strchr(fname, '/') || !(env_path = getenv("PATH"))) {

    if (sgf->fsrv.target_path) { ck_free(sgf->fsrv.target_path); }

    sgf->fsrv.target_path = ck_strdup(fname);

#ifdef __linux__
    if (sgf->fsrv.nyx_mode) {

      /* check if target_path is a nyx sharedir */
      if (stat(sgf->fsrv.target_path, &st) || S_ISDIR(st.st_mode)) {

        char *tmp = alloc_printf("%s/config.ron", sgf->fsrv.target_path);
        if (stat(tmp, &st) || S_ISREG(st.st_mode)) {

          free(tmp);
          return;

        }

      }

      FATAL("Directory '%s' not found or is not a nyx share directory",
            sgf->fsrv.target_path);

    }

#endif

    if (stat(sgf->fsrv.target_path, &st) || !S_ISREG(st.st_mode) ||
        !(st.st_mode & 0111) || (f_len = st.st_size) < 4) {

      FATAL("Program '%s' not found or not executable", fname);

    }

  } else {

    while (env_path) {

      u8 *cur_elem, *delim = strchr(env_path, ':');

      if (delim) {

        cur_elem = ck_alloc(delim - env_path + 1);
        if (unlikely(!cur_elem)) { FATAL("Unexpected large PATH"); }
        memcpy(cur_elem, env_path, delim - env_path);
        ++delim;

      } else {

        cur_elem = ck_strdup(env_path);

      }

      env_path = delim;

      if (sgf->fsrv.target_path) { ck_free(sgf->fsrv.target_path); }

      if (cur_elem[0]) {

        sgf->fsrv.target_path = alloc_printf("%s/%s", cur_elem, fname);

      } else {

        sgf->fsrv.target_path = ck_strdup(fname);

      }

      ck_free(cur_elem);

      if (!stat(sgf->fsrv.target_path, &st) && S_ISREG(st.st_mode) &&
          (st.st_mode & 0111) && (f_len = st.st_size) >= 4) {

        break;

      }

      ck_free(sgf->fsrv.target_path);
      sgf->fsrv.target_path = 0;

    }

    if (!sgf->fsrv.target_path) {

      FATAL("Program '%s' not found or not executable", fname);

    }

  }

  if (sgf->sgf_env.sgf_skip_bin_check || sgf->use_wine || sgf->unicorn_mode ||
      (sgf->fsrv.qemu_mode && getenv("SGF_QEMU_CUSTOM_BIN")) ||
      (sgf->fsrv.cs_mode && getenv("SGF_CS_CUSTOM_BIN")) ||
      sgf->non_instrumented_mode) {

    return;

  }

  /* Check for blatant user errors. */

  /*  disabled. not a real-worl scenario where this is a problem.
    if ((!strncmp(sgf->fsrv.target_path, "/tmp/", 5) &&
         !strchr(sgf->fsrv.target_path + 5, '/')) ||
        (!strncmp(sgf->fsrv.target_path, "/var/tmp/", 9) &&
         !strchr(sgf->fsrv.target_path + 9, '/'))) {

      FATAL("Please don't keep binaries in /tmp or /var/tmp");

    }

  */

  fd = open(sgf->fsrv.target_path, O_RDONLY);

  if (fd < 0) { PFATAL("Unable to open '%s'", sgf->fsrv.target_path); }

  f_data = mmap(0, f_len, PROT_READ, MAP_PRIVATE, fd, 0);

  if (f_data == MAP_FAILED) {

    PFATAL("Unable to mmap file '%s'", sgf->fsrv.target_path);

  }

  close(fd);

  if (f_data[0] == '#' && f_data[1] == '!') {

    SAYF("\n" cLRD "[-] " cRST
         "Oops, the target binary looks like a shell script. Some build "
         "systems will\n"
         "    sometimes generate shell stubs for dynamically linked programs; "
         "try static\n"
         "    library mode (./configure --disable-shared) if that's the "
         "case.\n\n"

         "    Another possible cause is that you are actually trying to use a "
         "shell\n"
         "    wrapper around the fuzzed component. Invoking shell can slow "
         "down the\n"
         "    fuzzing process by a factor of 20x or more; it's best to write "
         "the wrapper\n"
         "    in a compiled language instead.\n");

    FATAL("Program '%s' is a shell script", sgf->fsrv.target_path);

  }

#ifndef __APPLE__

  if (f_data[0] != 0x7f || memcmp(f_data + 1, "ELF", 3)) {

    FATAL("Program '%s' is not an ELF binary", sgf->fsrv.target_path);

  }

#else

  #if !defined(__arm__) && !defined(__arm64__)
  if ((f_data[0] != 0xCF || f_data[1] != 0xFA || f_data[2] != 0xED) &&
      (f_data[0] != 0xCA || f_data[1] != 0xFE || f_data[2] != 0xBA))
    FATAL("Program '%s' is not a 64-bit or universal Mach-O binary",
          sgf->fsrv.target_path);
  #endif

#endif                                                       /* ^!__APPLE__ */

  if (!sgf->fsrv.qemu_mode && !sgf->fsrv.frida_mode && !sgf->unicorn_mode &&
#ifdef __linux__
      !sgf->fsrv.nyx_mode &&
#endif
      !sgf->fsrv.cs_mode && !sgf->non_instrumented_mode &&
      !afl_memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR))) {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like the target binary is not instrumented! The fuzzer depends "
         "on\n"
         "    compile-time instrumentation to isolate interesting test cases "
         "while\n"
         "    mutating the input data. For more information, and for tips on "
         "how to\n"
         "    instrument binaries, please see %s/README.md.\n\n"

         "    When source code is not available, you may be able to leverage "
         "QEMU\n"
         "    mode support. Consult the README.md for tips on how to enable "
         "this.\n\n"

         "    If your target is an instrumented binary (e.g. with zafl, "
         "retrowrite,\n"
         "    etc.) then set 'SGF_SKIP_BIN_CHECK=1'\n\n"

         "    (It is also possible to use sgf-fuzz as a traditional, "
         "non-instrumented\n"
         "    fuzzer. For that use the -n option - but expect much worse "
         "results.)\n",
         doc_path);

    FATAL("No instrumentation detected");

  }

  if ((sgf->fsrv.cs_mode || sgf->fsrv.qemu_mode || sgf->fsrv.frida_mode) &&
      afl_memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR))) {

    SAYF("\n" cLRD "[-] " cRST
         "This program appears to be instrumented with AFL++ compilers, but is "
         "being run\n"
         "    in QEMU mode (-Q). This is probably not what you "
         "want -\n"
         "    this setup will be slow and offer no practical benefits.\n");

    if (!sgf->sgf_env.sgf_ignore_problems) {

      FATAL("Instrumentation found in -Q mode");

    }

  }

  sgf->fsrv.uses_asan = 0;

  if (afl_memmem(f_data, f_len, "__asan_init", 11)) {

    sgf->fsrv.uses_asan |= 1;

  }

  if (afl_memmem(f_data, f_len, "__lsan_init", 11)) {

    sgf->fsrv.uses_asan |= 2;

  }

  if (afl_memmem(f_data, f_len, "__msan_init", 11)) {

    sgf->fsrv.uses_asan |= 4;

  }

  /* Detect persistent & deferred init signatures in the binary. */

  if (afl_memmem(f_data, f_len, PERSIST_SIG, strlen(PERSIST_SIG))) {

    OKF(cPIN "Persistent mode binary detected.");
    setenv(PERSIST_ENV_VAR, "1", 1);
    sgf->persistent_mode = 1;
    sgf->fsrv.persistent_mode = 1;
    sgf->shmem_testcase_mode = 1;

  } else if (getenv("SGF_PERSISTENT")) {

    OKF(cPIN "Persistent mode enforced.");
    setenv(PERSIST_ENV_VAR, "1", 1);
    sgf->persistent_mode = 1;
    sgf->fsrv.persistent_mode = 1;
    sgf->shmem_testcase_mode = 1;

  } else if (getenv("SGF_FRIDA_PERSISTENT_ADDR")) {

    OKF("FRIDA Persistent mode configuration options detected.");
    setenv(PERSIST_ENV_VAR, "1", 1);
    sgf->persistent_mode = 1;
    sgf->fsrv.persistent_mode = 1;
    sgf->shmem_testcase_mode = 1;

  }

  if (sgf->fsrv.frida_mode ||
      afl_memmem(f_data, f_len, DEFER_SIG, strlen(DEFER_SIG))) {

    OKF(cPIN "Deferred forkserver binary detected.");
    setenv(DEFER_ENV_VAR, "1", 1);
    sgf->deferred_mode = 1;

  } else if (getenv("SGF_DEFER_FORKSRV")) {

    OKF(cPIN "Deferred forkserver enforced.");
    setenv(DEFER_ENV_VAR, "1", 1);
    sgf->deferred_mode = 1;

  }

  if (munmap(f_data, f_len)) { PFATAL("unmap() failed"); }

}

/* Check if we're on TTY. */

void check_if_tty(sgf_state_t *sgf) {

  struct winsize ws;

  if (sgf->sgf_env.sgf_no_ui) {

    OKF("Disabling the UI because SGF_NO_UI is set.");
    sgf->not_on_tty = 1;
    return;

  }

  if (ioctl(1, TIOCGWINSZ, &ws)) {

    if (errno == ENOTTY) {

      OKF("Looks like we're not running on a tty, so I'll be a bit less "
          "verbose.");
      sgf->not_on_tty = 1;

    }

    return;

  }

}

/* Set up signal handlers. More complicated that needs to be, because libc on
   Solaris doesn't resume interrupted reads(), sets SA_RESETHAND when you call
   siginterrupt(), and does other stupid things. */

void setup_signal_handlers(void) {

  struct sigaction sa;

  memset((void *)&sa, 0, sizeof(sa));
  sa.sa_handler = NULL;
#ifdef SA_RESTART
  sa.sa_flags = SA_RESTART;
#endif
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Window resize */

  sa.sa_handler = handle_resize;
  sigaction(SIGWINCH, &sa, NULL);

  /* SIGUSR1: skip entry */

  sa.sa_handler = handle_skipreq;
  sigaction(SIGUSR1, &sa, NULL);

  /* Things we don't care about. */

  sa.sa_handler = SIG_IGN;
  sigaction(SIGTSTP, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);

}

/* Make a copy of the current command line. */

void save_cmdline(sgf_state_t *sgf, u32 argc, char **argv) {

  u32 len = 1, i;
  u8 *buf;

  for (i = 0; i < argc; ++i) {

    len += strlen(argv[i]) + 1;

  }

  buf = sgf->orig_cmdline = ck_alloc(len);

  for (i = 0; i < argc; ++i) {

    u32 l = strlen(argv[i]);

    if (!argv[i] || !buf) { FATAL("null deref detected"); }

    memcpy(buf, argv[i], l);
    buf += l;

    if (i != argc - 1) { *(buf++) = ' '; }

  }

  *buf = 0;

}

