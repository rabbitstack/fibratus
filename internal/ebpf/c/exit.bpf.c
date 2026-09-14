//go:build ignore

#include "common/events.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* Process exits are captured from sched_process_exit rather than the
 * syscalls/sys_exit_{exit,exit_group} tracepoints: those syscalls never
 * return, so their exit tracepoints never fire. The scheduler hook also
 * covers processes terminated by signals, which never enter exit_group.
 */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(handle_sched_process_exit, struct task_struct *task)
{
	struct fibratus_event *e;
	struct task_struct *parent;
	const struct cred *cred;

	if (!task)
		return 0;

	/* Only emit process exits from the thread-group leader; thread
	 * exits are not process exits.
	 */
	if (task->pid != task->tgid)
		return 0;

	e = reserve_event();
	if (!e)
		return 0;

	e->kind = EVT_KIND_EXIT;
	e->type = EVT_TYPE_EXIT;
	/* Raw wait status: (code << 8) | termination signal. */
	e->retval = task->exit_code;
	e->pid = task->tgid;
	e->tid = task->pid;
	e->tgid = task->tgid;
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
