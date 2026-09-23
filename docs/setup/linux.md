# Linux

On Linux, Fibratus collects telemetry through eBPF CO-RE programs attached to syscall and scheduler tracepoints, instead of ETW. The rule engine, filters, actions, and outputs are the same on both platforms.

## Runtime prerequisites

These are hard requirements. Fibratus probes each one at startup and refuses to run if any is missing, rather than degrading to partial telemetry.

| Requirement | Why |
| --- | --- |
| Linux 5.9 or later | BPF task iterators, used to build the initial process tree, appear in 5.9 |
| Runtime kernel BTF at `/sys/kernel/btf/vmlinux` | CO-RE relocations and `iter/task` attachment resolve against the running kernel's own type information |
| `x86_64` | The shipped BPF objects are built for this architecture |
| Ring buffer map support | Events reach userspace through `BPF_MAP_TYPE_RINGBUF` |

There is no BTFHub download and no embedded build-host BTF. A kernel compiled without `CONFIG_DEBUG_INFO_BTF` cannot run the backend, and no amount of configuration works around it. Most distribution kernels from 5.9 onwards enable it; if `/sys/kernel/btf/vmlinux` is absent, the kernel was built without it.

Nothing needs to be compiled at install time. The BPF objects are generated ahead of time and committed, so neither clang nor kernel headers are required on the host.

## Capabilities

Running as root works. To run unprivileged, grant:

| Capability | Needed for |
| --- | --- |
| `CAP_BPF` | Loading programs and creating maps |
| `CAP_PERFMON` | Attaching to tracepoints |
| `CAP_SYS_PTRACE` | Reading `/proc/<pid>/exe` and `/proc/<pid>/cmdline` of processes owned by other users |
| `CAP_KILL` | Only if a rule uses the `kill` action against processes you do not own |

`CAP_BPF` and `CAP_PERFMON` were split out of `CAP_SYS_ADMIN` in 5.8. On a kernel that predates the split, or on a distribution that has not adopted it, `CAP_SYS_ADMIN` is the equivalent.

Two environment-specific cases override all of the above. Under kernel lockdown in `confidentiality` mode, loading tracing programs is refused no matter which capabilities you hold; check with `cat /sys/kernel/security/lockdown`. Below 5.11, BPF memory is charged against `RLIMIT_MEMLOCK`, so a low limit causes load failures that read as permission errors; Fibratus raises the limit at startup, which itself needs privilege.

## Reading a failed startup

Fibratus prints the probe result before anything else:

```
eBPF prerequisites ok: kernel=6.8.0-40-generic btf=/sys/kernel/btf/vmlinux ringbuf=true iter=true
```

When a prerequisite is missing it refuses to start and names every failure at once, so one run tells you everything that needs fixing:

```
eBPF prerequisites: kernel 5.4.0-91-generic is below required 5.9; usable kernel BTF required at /sys/kernel/btf/vmlinux
```

Failures after that line are attachment problems rather than prerequisite problems. `cannot create bpf perf link: permission denied` on an optional tracepoint is expected and harmless: `fork`, `vfork`, and the legacy `open`, `unlink`, and `rename` syscalls are skipped when the kernel refuses a perf link on them, because libc routes through `clone`, `openat`, `unlinkat`, and `renameat` anyway. The same message on a required tracepoint is fatal and means capabilities or lockdown.

## Process enrichment

The initial process tree comes from a single `iter/task` pass over `task_struct`, which is race-free against processes starting during startup. Executable paths and command lines are then filled in best effort from `/proc/<pid>/exe` and `/proc/<pid>/cmdline`.

That second step is allowed to fail. A process that exits between the iterator pass and the procfs read leaves those two fields empty, and Fibratus counts it rather than dropping the process. Enrichment never replaces what the iterator produced, so a failed read cannot corrupt process identity.

## Metrics

Counters are exported as expvars and available through `fibratus stats`.

| Metric | Meaning |
| --- | --- |
| `ebpf.events.processed` | Events decoded from the ring buffer |
| `ebpf.events.excluded` | Events dropped in userspace by config or filters |
| `ebpf.events.unknown` | Records carrying a type this build does not know |
| `ebpf.events.parse.errors` | Malformed ring buffer records |
| `ebpf.ringbuf.drops` | Events the kernel could not queue because the ring buffer was full |
| `ebpf.approver.drops` | Events rejected in the kernel by an approver, before reaching the ring buffer |
| `ebpf.enrichment.miss` | Processes whose procfs enrichment failed |
| `ebpf.startup.pending.queued` | Live events buffered while the baseline scan ran |
| `ebpf.startup.pending.dropped` | Live events discarded because that buffer was full |
| `ebpf.startup.replay.applied` | Buffered events replayed once the baseline completed |
| `ebpf.startup.snapshot.upserts` | Processes recorded by the baseline scan |
| `ebpf.startup.snapshot.late` | Baseline records that arrived after the switch to live dispatch |

`ebpf.ringbuf.drops` growing steadily is the signal that consumers are not keeping up; it is the one counter worth alerting on. `ebpf.approver.drops` growing is normal and desirable, since it counts work avoided.

## Building from source

Ordinary builds consume the committed objects:

```
make
```

Regenerating them needs clang, pinned to the major the committed objects were built with, because clang records its version in BTF and a different major rewrites every object:

```
make ebpf          # regenerate
make ebpf-drift    # regenerate and fail if the result differs from what is committed
```

Other targets: `make test`, `make test-race`, `make lint`, and `make test-integration`, which needs root and a host meeting the prerequisites above.
