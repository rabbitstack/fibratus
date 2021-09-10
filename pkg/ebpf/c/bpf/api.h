#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

/* helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

/* helper functions called from eBPF programs */

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
                (void *) BPF_FUNC_trace_printk;

/* macro for printing debug info to the tracing pipe, useful just for
 debugging purposes and not recommended to use in production systems.

 use `sudo cat /sys/kernel/debug/tracing/trace_pipe` to read debug info.
 */
#define klog(fmt, ...)                                                   \
            ({                                                             \
                char ____fmt[] = fmt;                                      \
                bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
            })

#define PERF_PUSH(map, evt)  u32 cpu = bpf_get_smp_processor_id(); \
                             bpf_perf_event_output(ctx, &map, \
                                                   cpu, \
                                                   &evt, sizeof(evt)); \

/* current task, pid, uid, command, timestamp, processor id */
static unsigned long long (*bpf_get_smp_processor_id)(void) =
                (void *) BPF_FUNC_get_smp_processor_id;
static unsigned long long (*bpf_get_current_pid_tgid)(void) =
                (void *) BPF_FUNC_get_current_pid_tgid;
static unsigned long long (*bpf_get_current_uid_gid)(void) =
                (void *) BPF_FUNC_get_current_uid_gid;
static int (*bpf_get_current_comm)(void *buf, int buf_size) =
                (void *) BPF_FUNC_get_current_comm;
static long (*bpf_get_current_task)(void) =
            (void *) BPF_FUNC_get_current_task;
static unsigned long long (*bpf_ktime_get_ns)(void) =
                (void *) BPF_FUNC_ktime_get_ns;

static int (*bpf_probe_read)(void *dst, int size, void *unsafe_ptr) =
        (void *) BPF_FUNC_probe_read;

static int (*bpf_probe_read_str)(void *dst, int size, const void *unsafe_ptr) =
    (void *) BPF_FUNC_probe_read_str;

/* eBPF maps */
static void *(*bpf_map_lookup_elem)(void *map, void *key) =
                (void *) BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, void *key, void *value,
                                  unsigned long long flags) =
                (void *) BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, void *key) =
                (void *) BPF_FUNC_map_delete_elem;

static void (*bpf_tail_call)(void *ctx, void *map, int index) =
        (void *)BPF_FUNC_tail_call;

static int (*bpf_perf_event_output)(void *ctx, void *map,
                                    unsigned long long flags, void *data,
                                    int size) =
                (void *) BPF_FUNC_perf_event_output;

#define BUF_SIZE_MAP_NS 256

struct bpf_map_def {
        unsigned int type;
        unsigned int key_size;
        unsigned int value_size;
        unsigned int max_entries;
        unsigned int map_flags;
        unsigned int pinning;
        char namespace[BUF_SIZE_MAP_NS];
};

#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_PARM6(x) ((x)->r9)
#define PT_REGS_RET(x) ((x)->sp)
#define PT_REGS_FP(x) ((x)->bp)
#define PT_REGS_RC(x) ((x)->ax)
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->ip)

#endif
