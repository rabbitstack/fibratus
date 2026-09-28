# Linux

On Linux, Fibratus collects telemetry through eBPF CO-RE programs attached to syscall and scheduler tracepoints, instead of ETW. The rule engine, filters, actions, and outputs are the same on both platforms.

## Installing

Packages are built for `x86_64` and carry the binary, a configuration, the shipped rules, and a systemd unit. The BPF objects are compiled into the binary, so there is nothing else to install and no compiler is needed on the host.

```
# Debian, Ubuntu
sudo dpkg -i fibratus_<version>_amd64.deb

# RHEL, Fedora, Rocky, openSUSE
sudo rpm -i fibratus-<version>-1.x86_64.rpm
```

| Path | Contents |
| --- | --- |
| `/usr/bin/fibratus` | The binary |
| `/etc/fibratus/fibratus.yml` | Configuration, preserved across upgrades |
| `/etc/fibratus/rules/` | Shipped detection rules |
| `/etc/fibratus/rules/macros/` | Macros the rules expand |
| `/lib/systemd/system/fibratus.service` | Service unit, `/usr/lib/...` on RPM distributions |

## Quick start

Check the host before starting anything. This refuses to run and names every unmet requirement at once, rather than failing later inside the capture:

```
sudo fibratus rules validate
```

Run in the foreground to see events as they arrive:

```
sudo fibratus run
```

Narrow it with a filter expression, using the same language the rules use:

```
sudo fibratus run "evt.name = 'openat' and file.path startswith '/etc'"
```

Then run it as a service:

```
sudo systemctl enable --now fibratus
sudo systemctl status fibratus
sudo journalctl -u fibratus -f
```

The unit logs to the journal. With the rule engine enabled, only events matching a rule reach the outputs, so an idle host is expected to be quiet; drop the rules or set `filters.rules.enabled` to `false` to see the raw stream.

Inspect a running instance over the API socket:

```
sudo fibratus config    # the configuration as loaded
sudo fibratus stats     # capture, drop, and rule engine counters
sudo fibratus list events
```

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

The packaged unit starts Fibratus as root, because attaching a syscall tracepoint reads its id from `/sys/kernel/tracing`, which is root-only on stock distributions. What limits it is the bounding set in the unit, which drops everything except the four capabilities below. Granting these to an unprivileged invocation works too, provided tracefs is readable:

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
make          # the binary
make pkg      # deb and rpm into build/pkg
```

Regenerating them needs clang, pinned to the major the committed objects were built with, because clang records its version in BTF and a different major rewrites every object:

```
make ebpf          # regenerate
make ebpf-drift    # regenerate and fail if the result differs from what is committed
```

Other targets: `make test`, `make test-race`, `make lint`, and `make test-integration`, which needs root and a host meeting the prerequisites above.
