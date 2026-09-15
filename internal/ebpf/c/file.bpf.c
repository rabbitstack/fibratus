//go:build ignore

#include "common/events.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

static __always_inline int handle_openat_enter(s64 dirfd, const char *pathname, u64 flags, u64 mode)
{
	struct scratch_value *val;

	if (!type_enabled(EVT_TYPE_OPENAT))
		return 0;
	val = borrow_scratch();
	if (!val)
		return 0;
	val->arg0 = (u64)dirfd;
	val->arg1 = mode;
	val->flags = flags;
	val->truncated |= read_user_str(val->filename, sizeof(val->filename), pathname);
	store_scratch(val);
	return 0;
}

SEC("tp/syscalls/sys_enter_open")
int handle_sys_enter_open(struct trace_event_raw_sys_enter *ctx)
{
	return handle_openat_enter(-100 /* AT_FDCWD */, (const char *)ctx->args[0], ctx->args[1], ctx->args[2]);
}

SEC("tp/syscalls/sys_exit_open")
int handle_sys_exit_open(struct trace_event_raw_sys_exit *ctx)
{
	return submit_from_scratch(EVT_TYPE_OPENAT, ctx->ret, (u32)ctx->id);
}

SEC("tp/syscalls/sys_enter_openat")
int handle_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	return handle_openat_enter((s64)ctx->args[0], (const char *)ctx->args[1], ctx->args[2], ctx->args[3]);
}

SEC("tp/syscalls/sys_exit_openat")
int handle_sys_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
	return submit_from_scratch(EVT_TYPE_OPENAT, ctx->ret, (u32)ctx->id);
}

SEC("tp/syscalls/sys_enter_openat2")
int handle_sys_enter_openat2(struct trace_event_raw_sys_enter *ctx)
{
	struct open_how how = {};

	if (ctx->args[2])
		bpf_probe_read_user(&how, sizeof(how), (const void *)ctx->args[2]);
	return handle_openat_enter((s64)ctx->args[0], (const char *)ctx->args[1], how.flags, how.mode);
}

SEC("tp/syscalls/sys_exit_openat2")
int handle_sys_exit_openat2(struct trace_event_raw_sys_exit *ctx)
{
	return submit_from_scratch(EVT_TYPE_OPENAT, ctx->ret, (u32)ctx->id);
}

static __always_inline int handle_unlink_enter(s64 dirfd, const char *pathname, u64 flags)
{
	struct scratch_value *val;

	if (!type_enabled(EVT_TYPE_UNLINK))
		return 0;
	val = borrow_scratch();
	if (!val)
		return 0;
	val->arg0 = (u64)dirfd;
	val->flags = flags;
	val->truncated |= read_user_str(val->filename, sizeof(val->filename), pathname);
	store_scratch(val);
	return 0;
}

SEC("tp/syscalls/sys_enter_unlink")
int handle_sys_enter_unlink(struct trace_event_raw_sys_enter *ctx)
{
	return handle_unlink_enter(-100 /* AT_FDCWD */, (const char *)ctx->args[0], 0);
}

SEC("tp/syscalls/sys_exit_unlink")
int handle_sys_exit_unlink(struct trace_event_raw_sys_exit *ctx)
{
	return submit_from_scratch(EVT_TYPE_UNLINK, ctx->ret, (u32)ctx->id);
}

SEC("tp/syscalls/sys_enter_unlinkat")
int handle_sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	return handle_unlink_enter((s64)ctx->args[0], (const char *)ctx->args[1], ctx->args[2]);
}

SEC("tp/syscalls/sys_exit_unlinkat")
int handle_sys_exit_unlinkat(struct trace_event_raw_sys_exit *ctx)
{
	return submit_from_scratch(EVT_TYPE_UNLINK, ctx->ret, (u32)ctx->id);
}

static __always_inline int handle_rename_enter(s64 olddirfd, const char *oldpath, s64 newdirfd, const char *newpath, u64 flags)
{
	struct scratch_value *val;

	if (!type_enabled(EVT_TYPE_RENAME))
		return 0;
	val = borrow_scratch();
	if (!val)
		return 0;
	val->arg0 = (u64)olddirfd;
	val->arg1 = (u64)newdirfd;
	val->flags = flags;
	val->truncated |= read_user_str(val->filename, sizeof(val->filename), oldpath);
	if (read_user_str(val->filename2, sizeof(val->filename2), newpath))
		val->truncated |= TRUNC_FILENAME2;
	store_scratch(val);
	return 0;
}

SEC("tp/syscalls/sys_enter_rename")
int handle_sys_enter_rename(struct trace_event_raw_sys_enter *ctx)
{
	return handle_rename_enter(-100 /* AT_FDCWD */, (const char *)ctx->args[0], -100, (const char *)ctx->args[1], 0);
}

SEC("tp/syscalls/sys_exit_rename")
int handle_sys_exit_rename(struct trace_event_raw_sys_exit *ctx)
{
	return submit_from_scratch(EVT_TYPE_RENAME, ctx->ret, (u32)ctx->id);
}

SEC("tp/syscalls/sys_enter_renameat")
int handle_sys_enter_renameat(struct trace_event_raw_sys_enter *ctx)
{
	return handle_rename_enter((s64)ctx->args[0], (const char *)ctx->args[1], (s64)ctx->args[2], (const char *)ctx->args[3], 0);
}

SEC("tp/syscalls/sys_exit_renameat")
int handle_sys_exit_renameat(struct trace_event_raw_sys_exit *ctx)
{
	return submit_from_scratch(EVT_TYPE_RENAME, ctx->ret, (u32)ctx->id);
}

SEC("tp/syscalls/sys_enter_renameat2")
int handle_sys_enter_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	return handle_rename_enter((s64)ctx->args[0], (const char *)ctx->args[1], (s64)ctx->args[2], (const char *)ctx->args[3], ctx->args[4]);
}

SEC("tp/syscalls/sys_exit_renameat2")
int handle_sys_exit_renameat2(struct trace_event_raw_sys_exit *ctx)
{
	return submit_from_scratch(EVT_TYPE_RENAME, ctx->ret, (u32)ctx->id);
}
