/* Minimal CO-RE type skeletons for the Linux eBPF spike.
 * Full kernel BTF is still required at load/attach time for iterators.
 */

#pragma once

typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;

typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

typedef __u32 __wsum;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;

typedef int pid_t;
typedef u32 uid_t;
typedef u32 gid_t;

struct kuid_t {
	uid_t val;
} __attribute__((preserve_access_index));

struct kgid_t {
	gid_t val;
} __attribute__((preserve_access_index));

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY = 8,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS = 13,
	BPF_MAP_TYPE_DEVMAP = 14,
	BPF_MAP_TYPE_SOCKMAP = 15,
	BPF_MAP_TYPE_CPUMAP = 16,
	BPF_MAP_TYPE_XSKMAP = 17,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE = 22,
	BPF_MAP_TYPE_STACK = 23,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_DEVMAP_HASH = 25,
	BPF_MAP_TYPE_STRUCT_OPS = 26,
	BPF_MAP_TYPE_RINGBUF = 27,
};

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct seq_file;

struct bpf_iter_meta {
	struct seq_file *seq;
	u64 session_id;
	u64 seq_num;
} __attribute__((preserve_access_index));

struct cred {
	struct kuid_t uid;
	struct kgid_t gid;
	struct kuid_t euid;
	struct kgid_t egid;
} __attribute__((preserve_access_index));

struct nsproxy {
	struct mnt_namespace *mnt_ns;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net *net_ns;
	struct cgroup_namespace *cgroup_ns;
} __attribute__((preserve_access_index));

struct mnt_namespace {
	unsigned int ns_inum;
} __attribute__((preserve_access_index));

struct uts_namespace {
	unsigned int ns_inum;
} __attribute__((preserve_access_index));

struct ipc_namespace {
	unsigned int ns_inum;
} __attribute__((preserve_access_index));

struct pid_namespace {
	unsigned int ns_inum;
} __attribute__((preserve_access_index));

struct net {
	unsigned int ns_inum;
} __attribute__((preserve_access_index));

struct cgroup_namespace {
	unsigned int ns_inum;
} __attribute__((preserve_access_index));

struct task_struct {
	int pid;
	int tgid;
	struct task_struct *real_parent;
	struct task_struct *group_leader;
	const struct cred *real_cred;
	struct nsproxy *nsproxy;
	u64 start_boottime;
	char comm[TASK_COMM_LEN];
} __attribute__((preserve_access_index));

struct bpf_iter__task {
	struct bpf_iter_meta *meta;
	struct task_struct *task;
} __attribute__((preserve_access_index));

/* Layout for sched/sched_process_exec; filename follows via __data_loc. */
struct trace_event_raw_sched_process_exec {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u32 __data_loc_filename;
	pid_t pid;
	pid_t old_pid;
};
