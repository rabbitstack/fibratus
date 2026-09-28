/* Shared event and map definitions for the Linux eBPF spike. */

#pragma once

#include "vmlinux.h"
#include "bpf_helpers.h"

#define SPIKE_FILENAME_LEN 256

enum spike_event_kind {
	SPIKE_EVENT_EXEC = 1,
	SPIKE_EVENT_SNAPSHOT = 2,
};

struct spike_event {
	u32 kind;
	u32 pid;
	u32 tgid;
	u32 ppid;
	u32 uid;
	u32 gid;
	u64 start_boottime;
	u64 timestamp_ns;
	u8 comm[TASK_COMM_LEN];
	u8 filename[SPIKE_FILENAME_LEN];
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

static __always_inline void spike_account_drop(void)
{
	u32 key = 0;
	u64 *count;

	count = bpf_map_lookup_elem(&drop_count, &key);
	if (!count)
		return;
	__sync_fetch_and_add(count, 1);
}
