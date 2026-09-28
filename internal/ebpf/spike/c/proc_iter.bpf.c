//go:build ignore

#include "events.h"
#include "bpf_core_read.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* Task iterator baseline scanner.
 *
 * Intentionally omits bpf_d_path (available from Linux 5.10). Executable path
 * and cmdline are left empty here and are filled best-effort from
 * /proc/<pid>/{exe,cmdline} in userspace.
 *
 * ctx->task is a trusted BTF pointer, so field access uses CO-RE direct reads
 * rather than bpf_probe_read-based helpers.
 */
SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
	struct task_struct *task;
	struct task_struct *parent;
	const struct cred *cred;
	struct spike_event *e;
	pid_t pid;
	pid_t tgid;

	task = ctx->task;
	if (!task)
		return 0;

	/* Emit one record per thread-group leader. */
	pid = task->pid;
	tgid = task->tgid;
	if (pid != tgid)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		spike_account_drop();
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->kind = SPIKE_EVENT_SNAPSHOT;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = pid;
	e->tgid = tgid;
	e->start_boottime = task->start_boottime;
	__builtin_memcpy(&e->comm, task->comm, sizeof(e->comm));

	parent = task->real_parent;
	if (parent)
		e->ppid = parent->tgid;

	cred = task->real_cred;
	if (cred) {
		e->uid = cred->uid.val;
		e->gid = cred->gid.val;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}
