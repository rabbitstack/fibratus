//go:build ignore

#include "common/events.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

static __always_inline int handle_kill_enter(u64 pid, u64 sig)
{
	struct scratch_value *val;

	if (!type_enabled(EVT_TYPE_KILL))
		return 0;
	val = borrow_scratch();
	if (!val)
		return 0;
	val->arg0 = pid;
	val->arg1 = sig;
	store_scratch(val);
	return 0;
}

SEC("tp/syscalls/sys_enter_kill")
int handle_sys_enter_kill(struct trace_event_raw_sys_enter *ctx)
{
	return handle_kill_enter(ctx->args[0], ctx->args[1]);
}

SEC("tp/syscalls/sys_exit_kill")
int handle_sys_exit_kill(struct trace_event_raw_sys_exit *ctx)
{
	return submit_from_scratch(EVT_TYPE_KILL, ctx->ret, (u32)ctx->id);
}

SEC("tp/syscalls/sys_enter_tkill")
int handle_sys_enter_tkill(struct trace_event_raw_sys_enter *ctx)
{
	return handle_kill_enter(ctx->args[0], ctx->args[1]);
}

SEC("tp/syscalls/sys_exit_tkill")
int handle_sys_exit_tkill(struct trace_event_raw_sys_exit *ctx)
{
	return submit_from_scratch(EVT_TYPE_KILL, ctx->ret, (u32)ctx->id);
}

SEC("tp/syscalls/sys_enter_tgkill")
int handle_sys_enter_tgkill(struct trace_event_raw_sys_enter *ctx)
{
	return handle_kill_enter(ctx->args[0], ctx->args[2]);
}

SEC("tp/syscalls/sys_exit_tgkill")
int handle_sys_exit_tgkill(struct trace_event_raw_sys_exit *ctx)
{
	return submit_from_scratch(EVT_TYPE_KILL, ctx->ret, (u32)ctx->id);
}

SEC("tp/syscalls/sys_enter_ptrace")
int handle_sys_enter_ptrace(struct trace_event_raw_sys_enter *ctx)
{
	struct scratch_value *val;

	if (!type_enabled(EVT_TYPE_PTRACE))
		return 0;
	val = borrow_scratch();
	if (!val)
		return 0;
	val->arg0 = ctx->args[0]; /* request */
	val->arg1 = ctx->args[1]; /* pid */
	val->arg2 = ctx->args[2]; /* addr */
	val->arg3 = ctx->args[3]; /* data */
	store_scratch(val);
	return 0;
}

SEC("tp/syscalls/sys_exit_ptrace")
int handle_sys_exit_ptrace(struct trace_event_raw_sys_exit *ctx)
{
	return submit_from_scratch(EVT_TYPE_PTRACE, ctx->ret, (u32)ctx->id);
}

SEC("tp/syscalls/sys_enter_prctl")
int handle_sys_enter_prctl(struct trace_event_raw_sys_enter *ctx)
{
	struct scratch_value *val;

	if (!type_enabled(EVT_TYPE_PRCTL))
		return 0;
	val = borrow_scratch();
	if (!val)
		return 0;
	val->arg0 = ctx->args[0];
	val->arg1 = ctx->args[1];
	val->arg2 = ctx->args[2];
	val->arg3 = ctx->args[3];
	val->flags = ctx->args[4];
	store_scratch(val);
	return 0;
}

SEC("tp/syscalls/sys_exit_prctl")
int handle_sys_exit_prctl(struct trace_event_raw_sys_exit *ctx)
{
	return submit_from_scratch(EVT_TYPE_PRCTL, ctx->ret, (u32)ctx->id);
}
