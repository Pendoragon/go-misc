// +build ignore

/* Copyright (c) 2016 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>

// Map that stores counts of times triggered, by PID.
BPF_HASH(counts_by_pid, u32, u64);

// Probe that counts every time it is triggered.
// Can be used to count things like syscalls or particular functions.
//int syscall__probe_counter(struct pt_regs* ctx) {
int syscall__probe_counter(struct pt_regs *ctx) {
  uint32_t tgid = bpf_get_current_pid_tgid() >> 32;

  counts_by_pid.increment(tgid);
  return 0;
}
