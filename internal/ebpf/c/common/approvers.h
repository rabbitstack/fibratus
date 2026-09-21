/* Conservative in-kernel approvers. Default-allow unless userspace
 * populated a proven superset of equality/list/prefix predicates.
 */

#pragma once

#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC (1U << 0)
#endif

#define APPR_REQ_PID  (1u << 0)
#define APPR_REQ_FILE (1u << 1)
#define APPR_REQ_PORT (1u << 2)

#define APPR_GENS 2
#define APPR_MODE_MAX (EVT_TYPE_MAX * APPR_GENS)

struct approver_pid_key {
	u32 gen;
	u32 type;
	u64 pid;
};

struct approver_port_key {
	u32 gen;
	u32 type;
	u16 port;
	u16 pad;
};

struct approver_file_key {
	u32 gen;
	u32 type;
	u8 path[EVT_FILENAME_LEN];
};

struct approver_lpm_key {
	u32 prefixlen;
	u8 path[EVT_FILENAME_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} approver_gen SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, APPR_MODE_MAX);
	__type(key, u32);
	__type(value, u8);
} approver_mode SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct approver_pid_key);
	__type(value, u8);
} approver_pid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct approver_port_key);
	__type(value, u8);
} approver_port SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct approver_file_key);
	__type(value, u8);
} approver_file_eq SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 256);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct approver_lpm_key);
	__type(value, u8);
} approver_file_pre_0 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 256);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct approver_lpm_key);
	__type(value, u8);
} approver_file_pre_1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct approver_file_key);
} approver_file_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct approver_lpm_key);
} approver_lpm_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} approver_reject SEC(".maps");

static __always_inline void account_approver_reject(void)
{
	u32 key = 0;
	u64 *count;

	count = bpf_map_lookup_elem(&approver_reject, &key);
	if (!count)
		return;
	__sync_fetch_and_add(count, 1);
}

static __always_inline u32 approver_generation(void)
{
	u32 key = 0;
	u32 *gen;

	gen = bpf_map_lookup_elem(&approver_gen, &key);
	if (!gen)
		return 0;
	return *gen & 1;
}

static __always_inline u16 sockaddr_dport(const u8 *aux)
{
	u16 family;
	u16 port;

	if (!aux)
		return 0;
	family = (u16)aux[0] | ((u16)aux[1] << 8);
	if (family != 2 && family != 10)
		return 0;
	port = ((u16)aux[2] << 8) | aux[3];
	return port;
}

static __always_inline int stash_filename(const u8 *filename)
{
	struct approver_file_key *exact;
	u32 zero = 0;

	exact = bpf_map_lookup_elem(&approver_file_heap, &zero);
	if (!exact)
		return 0;
	__builtin_memset(exact, 0, sizeof(*exact));
	if (filename)
		__builtin_memcpy(exact->path, filename, EVT_FILENAME_LEN);
	return 1;
}

static __always_inline int approver_file_match(u32 gen, u32 type)
{
	struct approver_file_key *exact;
	struct approver_lpm_key *lpm;
	u32 zero = 0;

	exact = bpf_map_lookup_elem(&approver_file_heap, &zero);
	if (exact) {
		exact->gen = gen;
		exact->type = type;
		if (bpf_map_lookup_elem(&approver_file_eq, exact))
			return 1;
		lpm = bpf_map_lookup_elem(&approver_lpm_heap, &zero);
		if (lpm) {
			__builtin_memset(lpm, 0, sizeof(*lpm));
			lpm->prefixlen = EVT_FILENAME_LEN * 8;
			__builtin_memcpy(lpm->path, exact->path, EVT_FILENAME_LEN);
			if (gen) {
				if (bpf_map_lookup_elem(&approver_file_pre_1, lpm))
					return 1;
			} else if (bpf_map_lookup_elem(&approver_file_pre_0, lpm)) {
				return 1;
			}
		}
	}
	return 0;
}

static __always_inline int event_approved(u32 type, u16 port, u32 truncated)
{
	u32 gen;
	u32 mode_key;
	u8 *mode;
	struct approver_pid_key pkey = {};
	struct approver_port_key rkey = {};

	if (type == EVT_TYPE_SNAPSHOT || type == EVT_TYPE_EXECVE ||
	    type == EVT_TYPE_EXIT || type == EVT_TYPE_CLONE)
		return 1;
	if (type >= EVT_TYPE_MAX)
		return 1;

	gen = approver_generation();
	mode_key = gen * EVT_TYPE_MAX + type;
	if (mode_key >= APPR_MODE_MAX)
		return 1;
	mode = bpf_map_lookup_elem(&approver_mode, &mode_key);
	if (!mode || *mode == 0)
		return 1;

	if (*mode & APPR_REQ_PID) {
		pkey.gen = gen;
		pkey.type = type;
		pkey.pid = bpf_get_current_pid_tgid() >> 32;
		if (!bpf_map_lookup_elem(&approver_pid, &pkey))
			return 0;
	}

	if (*mode & APPR_REQ_FILE) {
		if (!(truncated & TRUNC_FILENAME) &&
		    !approver_file_match(gen, type))
			return 0;
	}

	if (*mode & APPR_REQ_PORT) {
		rkey.gen = gen;
		rkey.type = type;
		rkey.port = port;
		if (!bpf_map_lookup_elem(&approver_port, &rkey))
			return 0;
	}

	return 1;
}
