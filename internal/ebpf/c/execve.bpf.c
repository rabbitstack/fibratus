//go:build ignore

#include "common/events.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

static __always_inline int handle_exec_enter(const char *filename, u32 syscall_id)
{
	struct scratch_value *val;

	val = borrow_scratch();
	if (!val)
		return 0;
	val->arg1 = syscall_id;
	val->truncated |= read_user_str(val->filename, sizeof(val->filename), filename);
	store_scratch(val);
	return 0;
}

static __always_inline int handle_exec_exit(long ret, u32 syscall_id)
{
	u64 key = bpf_get_current_pid_tgid();
	struct scratch_value *val;
	struct syscall_event *e;

	if (!type_enabled(EVT_TYPE_EXECVE)) {
		bpf_map_delete_elem(&scratch, &key);
		return 0;
	}

	e = reserve_event();
	if (!e) {
		bpf_map_delete_elem(&scratch, &key);
		return 0;
	}

	e->type = EVT_TYPE_EXECVE;
	e->syscall_id = syscall_id;
	e->retval = ret;
	fill_current_task(e);

	val = bpf_map_lookup_elem(&scratch, &key);
	if (val) {
		if (!e->syscall_id)
			e->syscall_id = (u32)val->arg1;
		copy_scratch(e, val);
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
