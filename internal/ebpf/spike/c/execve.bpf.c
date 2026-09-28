//go:build ignore

#include "events.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

SEC("tp/sched/sched_process_exec")
int handle_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct spike_event *e;
	struct task_struct *task;
	struct task_struct *parent;
	const struct cred *cred;
	u64 id;
	u32 fname_off;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		spike_account_drop();
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->kind = SPIKE_EVENT_EXEC;
	e->timestamp_ns = bpf_ktime_get_ns();

	id = bpf_get_current_pid_tgid();
	e->tgid = id >> 32;
	e->pid = (u32)id;
	e->uid = bpf_get_current_uid_gid();
	e->gid = bpf_get_current_uid_gid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	task = (struct task_struct *)bpf_get_current_task();
	e->start_boottime = BPF_CORE_READ(task, start_boottime);
	parent = BPF_CORE_READ(task, real_parent);
	if (parent)
		e->ppid = BPF_CORE_READ(parent, tgid);
	cred = BPF_CORE_READ(task, real_cred);
	if (cred) {
		e->uid = BPF_CORE_READ(cred, uid.val);
		e->gid = BPF_CORE_READ(cred, gid.val);
	}

	/* Filename is optional enrichment from the tracepoint payload. */
	fname_off = ctx->__data_loc_filename & 0xffff;
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
