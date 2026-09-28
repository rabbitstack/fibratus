//go:build ignore

#include "common/events.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* x86-64 syscall numbers. Register-only syscalls are captured at
 * tp_btf/sys_exit, which supplies pt_regs (args + retval) so there is
 * no enter probe or scratch slot. The per-syscall sys_exit tracepoint
 * only carries id and ret.
 */
#define NR_PTRACE 101
#define NR_KILL   62
#define NR_TKILL  200
#define NR_TGKILL 234
#define NR_PRCTL  157

SEC("tp_btf/sys_exit")
int BPF_PROG(handle_sys_exit, struct pt_regs *regs, long ret)
{
	u64 id;

	if (!regs)
		return 0;
	id = syscall_nr(regs);
	switch (id) {
	case NR_KILL:
	case NR_TKILL:
		return submit_args(EVT_TYPE_KILL, ret, (u32)id,
				   syscall_arg0(regs), syscall_arg1(regs), 0, 0, 0);
	case NR_TGKILL:
		/* pid, tid, sig: emit the thread-group id and the signal. */
		return submit_args(EVT_TYPE_KILL, ret, (u32)id,
				   syscall_arg0(regs), syscall_arg2(regs), 0, 0, 0);
	case NR_PTRACE:
		return submit_args(EVT_TYPE_PTRACE, ret, (u32)id,
				   syscall_arg0(regs), syscall_arg1(regs),
				   syscall_arg2(regs), syscall_arg3(regs), 0);
	case NR_PRCTL:
		return submit_args(EVT_TYPE_PRCTL, ret, (u32)id,
				   syscall_arg0(regs), syscall_arg1(regs),
				   syscall_arg2(regs), syscall_arg3(regs),
				   syscall_arg4(regs));
	default:
		return 0;
	}
}
