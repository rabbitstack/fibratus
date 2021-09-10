/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
 * https://www.fibratus.io
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#include <linux/types.h>

/* In Linux 5.4 asm_inline was introduced, but it's not supported by clang.
 * Redefine it to just asm to enable successful compilation.
 */

#ifdef asm_volatile_goto
#undef asm_volatile_goto
#define asm_volatile_goto(...) asm volatile("invalid use of asm_volatile_goto")
#endif

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif
#include <net/sock.h>

/* In Linux 5.4 asm_inline was introduced, but it's not supported by clang.
 * Redefine it to just asm to enable successful compilation.
 */
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#include <linux/bpf.h>
#include <linux/fdtable.h>

#include "bpf/api.h"
#include "kevent.h"
#include "maps.h"
#include "syscall.h"

#define _READ(P) ({ typeof(P) _val;				\
		    memset(&_val, 0, sizeof(_val));		\
		    bpf_probe_read(&_val, sizeof(_val), &P);	\
		    _val;					\
		 })

void tail_call(struct sys_exit_args *ctx, long syscall_id) {
    bpf_tail_call(ctx, &tracers, syscall_id);
}

bool __attribute__((always_inline)) discard_pid(struct kevent_header *khdr) {
    return bpf_map_lookup_elem(&pid_discarders, &khdr->pid) != NULL;
}

SEC("raw_tracepoint/sys_exit")
int sys_exit_tracepoint(struct sys_exit_args *ctx) {
    struct pt_regs *regs = (struct pt_regs *)ctx->regs;

	long id = _READ(regs->orig_ax);

    tail_call(ctx, id);
    return 0;
}

SEC("raw_tracepoint/sys_read")
int sys_read(struct sys_exit_args *ctx) {
    int offset = sizeof(struct kevent_header);
    u32 cpu = bpf_get_smp_processor_id();

    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct pt_regs *regs = (struct pt_regs *)ctx->regs;

	long id = _READ(regs->orig_ax);

    char *buf = bpf_map_lookup_elem(&buffer_area, &cpu);
    if (buf == NULL) {
        return 0;
    }

    struct kevent_header *khdr = (struct kevent_header *)buf;
    khdr->ts = bpf_ktime_get_ns();
    khdr->pid = pid_tgid >> 32;
    khdr->tid = pid_tgid & 0xffffffff;
    khdr->cpu = cpu;
    khdr->type = id;

    if (discard_pid(khdr)) {
        return 0;
    }

    int res = bpf_perf_event_output(ctx,
                         &perf,
                         BPF_F_CURRENT_CPU,
                         buf, offset & BUFFER_SIZE_MAX);
    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
