//go:build ignore

#include "common/events.h"
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
	struct syscall_event *e;
	pid_t pid;
	pid_t tgid;

	task = ctx->task;
	if (!task)
		return 0;

	pid = task->pid;
	tgid = task->tgid;
	if (pid != tgid)
		return 0;

	e = reserve_event();
	if (!e)
		return 0;

	e->type = EVT_TYPE_SNAPSHOT;
	e->pid = tgid;
	e->tid = pid;
	e->tgid = tgid;
	e->start_boottime = task->start_boottime;
	__builtin_memcpy(&e->comm, task->comm, sizeof(e->comm));

	parent = task->real_parent;
	if (parent)
		e->ppid = parent->tgid;

	cred = task->real_cred;
	if (cred) {
		e->uid = cred->euid.val;
		e->gid = cred->egid.val;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}
