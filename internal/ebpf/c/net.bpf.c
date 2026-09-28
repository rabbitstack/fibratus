//go:build ignore

#include "common/events.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* Copy exactly addrlen bytes: a fixed-size read past the caller's sockaddr
 * can cross into an unmapped page and fail wholesale, losing the address.
 */
static __always_inline void read_sockaddr(struct scratch_value *val, const void *addr, u64 addrlen)
{
	u64 len = addrlen;

	if (len > sizeof(val->aux)) {
		len = sizeof(val->aux);
		val->truncated |= TRUNC_AUX;
	}
	if (addr && len)
		bpf_probe_read_user(val->aux, len, addr);
}

SEC("tp/syscalls/sys_enter_connect")
int handle_sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct scratch_value *val;

	if (!type_enabled(EVT_TYPE_CONNECT))
		return 0;
	val = borrow_scratch();
	if (!val)
		return 0;
	val->arg0 = ctx->args[0];
	val->arg1 = ctx->args[2];
	read_sockaddr(val, (const void *)ctx->args[1], ctx->args[2]);
	store_scratch(val);
	return 0;
}

SEC("tp/syscalls/sys_exit_connect")
int handle_sys_exit_connect(struct trace_event_raw_sys_exit *ctx)
{
	return submit_from_scratch(EVT_TYPE_CONNECT, ctx->ret, (u32)ctx->id);
}

static __always_inline int handle_accept_enter(u64 fd, const void *addr, const void *addrlen, u64 flags)
{
	struct scratch_value *val;

	if (!type_enabled(EVT_TYPE_ACCEPT))
		return 0;
	val = borrow_scratch();
	if (!val)
		return 0;
	val->arg0 = fd;
	val->arg1 = (u64)addrlen;
	val->arg2 = (u64)addr;
	val->flags = flags;
	store_scratch(val);
	return 0;
}

/* addrlen is value-result: the kernel writes the peer address and its actual
 * size only once accept returns, so the sockaddr is copied at exit.
 */
static __always_inline int handle_accept_exit(long ret, u32 syscall_id)
{
	u64 key = bpf_get_current_pid_tgid();
	struct scratch_value *val;
	u32 addrlen = 0;

	val = bpf_map_lookup_elem(&scratch, &key);
	if (val && val->arg2 && ret >= 0) {
		if (val->arg1)
			bpf_probe_read_user(&addrlen, sizeof(addrlen), (const void *)val->arg1);
		read_sockaddr(val, (const void *)val->arg2, addrlen);
	}
	return submit_from_scratch(EVT_TYPE_ACCEPT, ret, syscall_id);
}

SEC("tp/syscalls/sys_enter_accept")
int handle_sys_enter_accept(struct trace_event_raw_sys_enter *ctx)
{
	return handle_accept_enter(ctx->args[0], (const void *)ctx->args[1], (const void *)ctx->args[2], 0);
}

SEC("tp/syscalls/sys_exit_accept")
int handle_sys_exit_accept(struct trace_event_raw_sys_exit *ctx)
{
	return handle_accept_exit(ctx->ret, (u32)ctx->id);
}

SEC("tp/syscalls/sys_enter_accept4")
int handle_sys_enter_accept4(struct trace_event_raw_sys_enter *ctx)
{
	return handle_accept_enter(ctx->args[0], (const void *)ctx->args[1], (const void *)ctx->args[2], ctx->args[3]);
}

SEC("tp/syscalls/sys_exit_accept4")
int handle_sys_exit_accept4(struct trace_event_raw_sys_exit *ctx)
{
	return handle_accept_exit(ctx->ret, (u32)ctx->id);
}
