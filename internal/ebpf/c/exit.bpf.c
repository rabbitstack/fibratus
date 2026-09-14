//go:build ignore

#include "common/events.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

static __always_inline int handle_exit(long ret, u32 syscall_id)
{
	struct fibratus_event *e;
	struct task_struct *task;
	struct task_struct *parent;
	const struct cred *cred;
	u64 id;

	id = bpf_get_current_pid_tgid();
	/* Only emit process exits from the thread-group leader. */
	if ((u32)id != (id >> 32))
		return 0;

	e = reserve_event();
	if (!e)
		return 0;

	e->kind = EVT_KIND_EXIT;
	e->type = EVT_TYPE_EXIT;
	e->syscall_id = syscall_id;
	e->retval = ret;
	fill_current_ids(e);

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

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_exit_group")
int handle_sys_exit_exit_group(struct trace_event_raw_sys_exit *ctx)
{
	return handle_exit(ctx->ret, (u32)ctx->id);
}

SEC("tp/syscalls/sys_exit_exit")
int handle_sys_exit_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_exit(ctx->ret, (u32)ctx->id);
}
