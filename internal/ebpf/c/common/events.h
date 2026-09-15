/* Shared event and map definitions for the Linux eBPF backend. */

#pragma once

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

#ifndef BPF_ANY
#define BPF_ANY 0
#endif

#define EVT_FILENAME_LEN 256
#define EVT_TYPE_MAX 32

#define TRUNC_FILENAME  (1u << 0)
#define TRUNC_FILENAME2 (1u << 1)

/* UAPI openat2 argument; not a CO-RE kernel type. */
struct open_how {
	u64 flags;
	u64 mode;
	u64 resolve;
};

struct trace_event_raw_sys_enter {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	long id;
	unsigned long args[6];
};

struct trace_event_raw_sys_exit {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	long id;
	long ret;
};

/* Stable semantic type IDs. Keep in sync with pkg/event.Type on Linux.
 * Zero is reserved for iter/task baseline snapshot records, which feed
 * the process state and are never dispatched as events.
 */
#define EVT_TYPE_SNAPSHOT 0
#define EVT_TYPE_EXECVE 1
#define EVT_TYPE_EXIT 2
#define EVT_TYPE_CLONE 3
#define EVT_TYPE_OPENAT 4
#define EVT_TYPE_UNLINK 5
#define EVT_TYPE_RENAME 6
#define EVT_TYPE_CONNECT 7
#define EVT_TYPE_ACCEPT 8
#define EVT_TYPE_MMAP 9
#define EVT_TYPE_PROCESS_VM_READ 10
#define EVT_TYPE_PROCESS_VM_WRITE 11
#define EVT_TYPE_KILL 12
#define EVT_TYPE_PTRACE 13
#define EVT_TYPE_PRCTL 14

struct syscall_event {
	u32 type;
	u32 pid;
	u32 tid;
	u32 tgid;
	u32 ppid;
	u32 uid;
	u32 gid;
	u32 syscall_id;
	s64 retval;
	/* Interpreted per event type: clone flags, open flags, mmap flags, accept flags. */
	u64 flags;
	u64 arg0;
	u64 arg1;
	u64 arg2;
	u64 arg3;
	u64 start_boottime;
	u64 timestamp_ns;
	u32 truncated;
	u32 pad;
	u8 comm[TASK_COMM_LEN];
	u8 filename[EVT_FILENAME_LEN];
	u8 filename2[EVT_FILENAME_LEN];
};

struct scratch_value {
	u64 arg0;
	u64 arg1;
	u64 arg2;
	u64 arg3;
	u64 flags;
	u32 truncated;
	u32 pad;
	u8 filename[EVT_FILENAME_LEN];
	u8 filename2[EVT_FILENAME_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} drop_count SEC(".maps");

/* Correlates sys_enter state with the matching sys_exit. The task can
 * migrate CPUs between entry and exit, so this must be a global hash, not
 * a per-CPU one. LRU eviction reclaims entries whose exit never fired
 * (e.g. the task was killed mid-syscall).
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 2048);
	__type(key, u64);
	__type(value, struct scratch_value);
} scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct scratch_value);
} scratch_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, EVT_TYPE_MAX);
	__type(key, u32);
	__type(value, u8);
} enabled SEC(".maps");

static __always_inline void account_drop(void)
{
	u32 key = 0;
	u64 *count;

	count = bpf_map_lookup_elem(&drop_count, &key);
	if (!count)
		return;
	__sync_fetch_and_add(count, 1);
}

static __always_inline int type_enabled(u32 type)
{
	u8 *on;

	if (type >= EVT_TYPE_MAX)
		return 0;
	on = bpf_map_lookup_elem(&enabled, &type);
	return on && *on;
}

static __always_inline struct syscall_event *reserve_event(void)
{
	struct syscall_event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		account_drop();
		return NULL;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->timestamp_ns = bpf_ktime_get_ns();
	return e;
}

static __always_inline void fill_current_ids(struct syscall_event *e)
{
	u64 id = bpf_get_current_pid_tgid();
	u64 uidgid = bpf_get_current_uid_gid();

	e->tgid = id >> 32;
	e->tid = (u32)id;
	e->pid = e->tgid;
	e->uid = (u32)uidgid;
	e->gid = uidgid >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline void fill_current_task(struct syscall_event *e)
{
	struct task_struct *task;
	struct task_struct *parent;
	const struct cred *cred;

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
}

static __always_inline u32 read_user_str(void *dst, u32 size, const char *src)
{
	long n;

	if (!src)
		return 0;
	n = bpf_probe_read_user_str(dst, size, src);
	if (n == size)
		return 1;
	return 0;
}

static __always_inline void copy_scratch(struct syscall_event *e, struct scratch_value *val)
{
	if (!val)
		return;
	e->arg0 = val->arg0;
	e->arg1 = val->arg1;
	e->arg2 = val->arg2;
	e->arg3 = val->arg3;
	if (!e->flags)
		e->flags = val->flags;
	e->truncated = val->truncated;
	__builtin_memcpy(&e->filename, val->filename, sizeof(e->filename));
	__builtin_memcpy(&e->filename2, val->filename2, sizeof(e->filename2));
}

static __always_inline struct scratch_value *borrow_scratch(void)
{
	u32 zero = 0;
	struct scratch_value *val;

	val = bpf_map_lookup_elem(&scratch_heap, &zero);
	if (!val)
		return NULL;
	__builtin_memset(val, 0, sizeof(*val));
	return val;
}

static __always_inline int store_scratch(struct scratch_value *val)
{
	u64 key = bpf_get_current_pid_tgid();

	return bpf_map_update_elem(&scratch, &key, val, BPF_ANY);
}

static __always_inline int submit_from_scratch(u32 type, long ret, u32 syscall_id)
{
	u64 key = bpf_get_current_pid_tgid();
	struct scratch_value *val;
	struct syscall_event *e;

	if (!type_enabled(type)) {
		bpf_map_delete_elem(&scratch, &key);
		return 0;
	}

	e = reserve_event();
	if (!e) {
		bpf_map_delete_elem(&scratch, &key);
		return 0;
	}

	e->type = type;
	e->syscall_id = syscall_id;
	e->retval = ret;
	fill_current_task(e);
	val = bpf_map_lookup_elem(&scratch, &key);
	if (val)
		copy_scratch(e, val);
	bpf_map_delete_elem(&scratch, &key);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
