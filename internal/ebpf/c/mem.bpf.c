//go:build ignore

#include "common/events.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct iovec {
	u64 iov_base;
	u64 iov_len;
};

SEC("tp/syscalls/sys_enter_mmap")
int handle_sys_enter_mmap(struct trace_event_raw_sys_enter *ctx)
{
	struct scratch_value *val;

	if (!type_enabled(EVT_TYPE_MMAP))
		return 0;
	val = borrow_scratch();
	if (!val)
		return 0;
	val->arg0 = ctx->args[5]; /* offset */
	val->arg1 = ctx->args[1]; /* length */
	val->arg2 = ctx->args[2]; /* prot */
	val->arg3 = ctx->args[4]; /* fd */
	val->flags = ctx->args[3];
	store_scratch(val);
	return 0;
}

SEC("tp/syscalls/sys_exit_mmap")
int handle_sys_exit_mmap(struct trace_event_raw_sys_exit *ctx)
{
	return submit_from_scratch(EVT_TYPE_MMAP, ctx->ret, (u32)ctx->id);
}

static __always_inline int handle_process_vm_enter(u32 type, u64 pid, const void *rvec, u64 flags)
{
	struct scratch_value *val;
	struct iovec iov = {};

	if (!type_enabled(type))
		return 0;
	val = borrow_scratch();
	if (!val)
		return 0;
	val->arg0 = pid;
	val->flags = flags;
	if (rvec) {
		bpf_probe_read_user(&iov, sizeof(iov), rvec);
		val->arg2 = iov.iov_base;
		val->arg3 = iov.iov_len;
	}
	store_scratch(val);
	return 0;
}

SEC("tp/syscalls/sys_enter_process_vm_readv")
int handle_sys_enter_process_vm_readv(struct trace_event_raw_sys_enter *ctx)
{
	return handle_process_vm_enter(EVT_TYPE_PROCESS_VM_READ, ctx->args[0], (const void *)ctx->args[3], ctx->args[5]);
}

SEC("tp/syscalls/sys_exit_process_vm_readv")
int handle_sys_exit_process_vm_readv(struct trace_event_raw_sys_exit *ctx)
{
	return submit_from_scratch(EVT_TYPE_PROCESS_VM_READ, ctx->ret, (u32)ctx->id);
}

SEC("tp/syscalls/sys_enter_process_vm_writev")
int handle_sys_enter_process_vm_writev(struct trace_event_raw_sys_enter *ctx)
{
	return handle_process_vm_enter(EVT_TYPE_PROCESS_VM_WRITE, ctx->args[0], (const void *)ctx->args[3], ctx->args[5]);
}

SEC("tp/syscalls/sys_exit_process_vm_writev")
int handle_sys_exit_process_vm_writev(struct trace_event_raw_sys_exit *ctx)
{
	return submit_from_scratch(EVT_TYPE_PROCESS_VM_WRITE, ctx->ret, (u32)ctx->id);
}
