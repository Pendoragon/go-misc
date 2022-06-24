// +build ignore

#include <linux/sched.h>
#include <linux/version.h>

struct counts_key_t {
  u32 tgid;
  u64 ts; // Timestamp when the process started.
};

// Map that stores counts of times triggered, by PID.
BPF_HASH(counts_by_pid_ts, struct counts_key_t, u64);
// Probe that counts every time it is triggered.
// Can be used to count things like syscalls or particular functions.
int syscall__probe_counter(struct pt_regs* ctx) {
  uint32_t tgid = bpf_get_current_pid_tgid() >> 32;
  struct counts_key_t process_id = {};

  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  struct task_struct* group_leader_ptr = task->group_leader;

// Effectively returns task->group_leader->real_start_time;
// Note that after Linux 5.5, real_start_time was called start_boottime.
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
  u64 start_time = group_leader_ptr->real_start_time;
#else
  u64 start_time = group_leader_ptr->start_boottime;
#endif

  process_id.tgid = tgid;
  process_id.ts = div_u64(start_time, NSEC_PER_SEC / USER_HZ);
  counts_by_pid_ts.increment(process_id);

  return 0;
}
