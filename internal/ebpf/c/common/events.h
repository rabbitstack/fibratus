/* Shared event and map definitions for the Linux eBPF backend. */

#pragma once

#include "vmlinux.h"
#include "bpf_helpers.h"

#ifndef BPF_ANY
#define BPF_ANY 0
#endif

#define EVT_FILENAME_LEN 256

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
	/* Interpreted per event type; clone stores the raw clone flags. */
	u64 flags;
	u64 start_boottime;
	u64 timestamp_ns;
	u8 comm[TASK_COMM_LEN];
	u8 filename[EVT_FILENAME_LEN];
};

struct scratch_value {
	u64 arg0;
	u64 arg1;
	u8 filename[EVT_FILENAME_LEN];
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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, struct scratch_value);
} scratch SEC(".maps");

static __always_inline void account_drop(void)
{
	u32 key = 0;
	u64 *count;

	count = bpf_map_lookup_elem(&drop_count, &key);
	if (!count)
		return;
	__sync_fetch_and_add(count, 1);
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
