// +build ignore

/* Copyright (c) 2016 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
/* #include <linux/ptrace.h> */
#include <uapi/linux/bpf.h>
#include <uapi/linux/bpf_perf_event.h>
#include <uapi/linux/perf_event.h>
/* #include <bpf/bpf_helpers.h> */
/* #include <bpf/bpf_tracing.h> */
/* #include "vmlinux.h" */
/* #include "bpf_helpers.h" */
/* #include "bpf_tracing.h" */

#define TASK_COMM_LEN 16
// Max depth of each stack trace to track
#define PERF_MAX_STACK_DEPTH 127

struct key_t {
	char comm[TASK_COMM_LEN];
	int kernstack;
	int userstack;
};

BPF_HASH(counts, struct key_t, u64, 10000);
BPF_STACK_TRACE(stackmap, 10000);

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

int bpf_prog1(struct bpf_perf_event_data *ctx)
{
	/* char time_fmt1[] = "Time Enabled: %llu, Time Running: %llu"; */
	/* char time_fmt2[] = "Get Time Failed, ErrCode: %d"; */
	/* char addr_fmt[] = "Address recorded on event: %llx"; */
	/* char fmt[] = "CPU-%d period %lld ip %llx"; */
	u32 cpu = bpf_get_smp_processor_id();
	struct bpf_perf_event_value value_buf;
	struct key_t key;
	u64 *val, one = 1;
	int ret;

	if (ctx->sample_period < 10000)
		/* ignore warmup */
		return 0;

	bpf_get_current_comm(&key.comm, sizeof(key.comm));
	key.kernstack = stackmap.get_stackid(ctx, KERN_STACKID_FLAGS);
	key.userstack = stackmap.get_stackid(ctx, USER_STACKID_FLAGS);
	if ((int)key.kernstack < 0 && (int)key.userstack < 0) {
		/* bpf_trace_printk("CPU-%d period %lld ip %llx", cpu, ctx->sample_period, */
		/* 		 PT_REGS_IP(&ctx->regs)); */
		return 0;
	}

	ret = bpf_perf_prog_read_value(ctx, (void *)&value_buf, sizeof(struct bpf_perf_event_value));
	/* if (!ret) */
	/*   bpf_trace_printk("Time Enabled: %llu, Time Running: %llu", value_buf.enabled, value_buf.running); */
	/* else */
	/*   bpf_trace_printk("Get Time Failed, ErrCode: %d", ret); */

	/* if (ctx->addr != 0) */
	/*   bpf_trace_printk("Address recorded on event: %llx", ctx->addr); */

	/* val = bpf_map_lookup_elem(&counts, &key); */
	/* if (val) */
	/* 	(*val)++; */
	/* else */
	/* 	bpf_map_update_elem(&counts, &key, &one, BPF_NOEXIST); */
  counts.increment(key);
	return 0;
}

/* char _license[] SEC("license") = "GPL"; */
