//go:build ignore

#include "common/events.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

static __always_inline int handle_clone_enter(u64 flags, u32 syscall_id)
{
	u64 key = bpf_get_current_pid_tgid();
	struct scratch_value val = {};

	val.arg0 = flags;
	val.arg1 = syscall_id;
	bpf_map_update_elem(&scratch, &key, &val, BPF_ANY);
	return 0;
}

static __always_inline int handle_clone_exit(long ret, u32 syscall_id)
{
	u64 key = bpf_get_current_pid_tgid();
	struct scratch_value *val;
	struct syscall_event *e;
	struct task_struct *task;
	struct task_struct *parent;
	const struct cred *cred;

	/* Successful clones are emitted from sched_process_fork with child identity.
	 * Leave scratch in place so the fork handler can recover clone flags.
	 */
	if (ret >= 0)
		return 0;

	e = reserve_event();
	if (!e)
		return 0;

	e->type = EVT_TYPE_CLONE;
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
		e->uid = BPF_CORE_READ(cred, euid.val);
		e->gid = BPF_CORE_READ(cred, egid.val);
	}

	val = bpf_map_lookup_elem(&scratch, &key);
	if (val) {
		e->flags = val->arg0;
		if (!e->syscall_id)
			e->syscall_id = (u32)val->arg1;
	}
	bpf_map_delete_elem(&scratch, &key);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_clone")
int handle_sys_enter_clone(struct trace_event_raw_sys_enter *ctx)
{
	return handle_clone_enter(ctx->args[0], (u32)ctx->id);
}

SEC("tp/syscalls/sys_exit_clone")
int handle_sys_exit_clone(struct trace_event_raw_sys_exit *ctx)
{
	return handle_clone_exit(ctx->ret, (u32)ctx->id);
}

SEC("tp/syscalls/sys_enter_clone3")
int handle_sys_enter_clone3(struct trace_event_raw_sys_enter *ctx)
{
	u64 flags = 0;

	bpf_probe_read_user(&flags, sizeof(flags), (const void *)ctx->args[0]);
	return handle_clone_enter(flags, (u32)ctx->id);
}

SEC("tp/syscalls/sys_exit_clone3")
int handle_sys_exit_clone3(struct trace_event_raw_sys_exit *ctx)
{
	return handle_clone_exit(ctx->ret, (u32)ctx->id);
}

SEC("tp/syscalls/sys_enter_fork")
int handle_sys_enter_fork(struct trace_event_raw_sys_enter *ctx)
{
	return handle_clone_enter(0, (u32)ctx->id);
}

SEC("tp/syscalls/sys_exit_fork")
int handle_sys_exit_fork(struct trace_event_raw_sys_exit *ctx)
{
	return handle_clone_exit(ctx->ret, (u32)ctx->id);
}

SEC("tp/syscalls/sys_enter_vfork")
int handle_sys_enter_vfork(struct trace_event_raw_sys_enter *ctx)
{
	return handle_clone_enter(0, (u32)ctx->id);
}

SEC("tp/syscalls/sys_exit_vfork")
int handle_sys_exit_vfork(struct trace_event_raw_sys_exit *ctx)
{
	return handle_clone_exit(ctx->ret, (u32)ctx->id);
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(handle_sched_process_fork, struct task_struct *parent, struct task_struct *child)
{
	struct syscall_event *e;
	struct scratch_value *val;
	const struct cred *cred;
	struct task_struct *real_parent;
	u64 key;

	if (!child || !parent)
		return 0;

	e = reserve_event();
	if (!e)
		return 0;

	e->type = EVT_TYPE_CLONE;
	e->retval = child->tgid;
	e->pid = child->tgid;
	e->tid = child->pid;
	e->tgid = child->tgid;
	e->start_boottime = child->start_boottime;
	__builtin_memcpy(&e->comm, child->comm, sizeof(e->comm));

	real_parent = child->real_parent;
	if (real_parent)
		e->ppid = real_parent->tgid;
	else
		e->ppid = parent->tgid;

	cred = child->real_cred;
	if (cred) {
		e->uid = cred->euid.val;
		e->gid = cred->egid.val;
	}

	key = ((u64)parent->tgid << 32) | (u32)parent->pid;
	val = bpf_map_lookup_elem(&scratch, &key);
	if (val) {
		e->flags = val->arg0;
		e->syscall_id = (u32)val->arg1;
		bpf_map_delete_elem(&scratch, &key);
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}
