//go:build ignore

#include "common/events.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

static __always_inline int handle_exec_enter(const char *filename, u32 syscall_id)
{
	u64 key = bpf_get_current_pid_tgid();
	struct scratch_value val = {};

	val.arg1 = syscall_id;
	if (filename)
		bpf_probe_read_user_str(&val.filename, sizeof(val.filename), filename);
	bpf_map_update_elem(&scratch, &key, &val, BPF_ANY);
	return 0;
}

static __always_inline int handle_exec_exit(long ret, u32 syscall_id)
{
	u64 key = bpf_get_current_pid_tgid();
	struct scratch_value *val;
	struct fibratus_event *e;
	struct task_struct *task;
	struct task_struct *parent;
	const struct cred *cred;

	e = reserve_event();
	if (!e)
		return 0;

	e->kind = EVT_KIND_EXECVE;
	e->type = EVT_TYPE_EXECVE;
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

	val = bpf_map_lookup_elem(&scratch, &key);
	if (val) {
		if (!e->syscall_id)
			e->syscall_id = (u32)val->arg1;
		__builtin_memcpy(&e->filename, val->filename, sizeof(e->filename));
	}
	bpf_map_delete_elem(&scratch, &key);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_execve")
int handle_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	return handle_exec_enter((const char *)ctx->args[0], (u32)ctx->id);
}

SEC("tp/syscalls/sys_exit_execve")
int handle_sys_exit_execve(struct trace_event_raw_sys_exit *ctx)
{
	return handle_exec_exit(ctx->ret, (u32)ctx->id);
}

SEC("tp/syscalls/sys_enter_execveat")
int handle_sys_enter_execveat(struct trace_event_raw_sys_enter *ctx)
{
	return handle_exec_enter((const char *)ctx->args[1], (u32)ctx->id);
}

SEC("tp/syscalls/sys_exit_execveat")
int handle_sys_exit_execveat(struct trace_event_raw_sys_exit *ctx)
{
	return handle_exec_exit(ctx->ret, (u32)ctx->id);
}
