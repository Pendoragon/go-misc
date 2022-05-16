// +build ignore

/* Copyright (c) 2016 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <uapi/linux/bpf.h>
#include <uapi/linux/bpf_perf_event.h>
#include <uapi/linux/perf_event.h>

#define TASK_COMM_LEN 16
// Max depth of each stack trace to track
#define PERF_MAX_STACK_DEPTH 127

struct key_t {
	char comm[TASK_COMM_LEN];
  u32 pid;
	int kernstack;
	int userstack;
};

BPF_HASH(counts, struct key_t, u64, 10000);
BPF_STACK_TRACE(stackmap, 10000);

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

int bpf_prog1(struct bpf_perf_event_data *ctx)
{
	u32 cpu = bpf_get_smp_processor_id();
  // see https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#4-bpf_get_current_pid_tgid
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;
  u32 pid = id;
	struct bpf_perf_event_value value_buf;
	struct key_t key;
	u64 *val, one = 1;
	int ret;

  bpf_trace_printk("CPU-%d period %lld ip %llx", cpu, ctx->sample_period,
                   PT_REGS_IP(&ctx->regs));

	bpf_get_current_comm(&key.comm, sizeof(key.comm));
	key.kernstack = stackmap.get_stackid(ctx, KERN_STACKID_FLAGS);
	key.userstack = stackmap.get_stackid(ctx, USER_STACKID_FLAGS);
  key.pid = tgid;
	if ((int)key.kernstack < 0 && (int)key.userstack < 0) {
		bpf_trace_printk("CPU-%d period %lld ip %llx", cpu, ctx->sample_period,
                     PT_REGS_IP(&ctx->regs));
		return 0;
	}

	ret = bpf_perf_prog_read_value(ctx, (void *)&value_buf, sizeof(struct bpf_perf_event_value));

  counts.increment(key);
	return 0;
}
