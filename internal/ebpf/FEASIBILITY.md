# Linux eBPF Feasibility Notes

This note records the runtime contract, tooling, and build-gating work validated by the throwaway spike under `internal/ebpf/spike`.

## Runtime contract

Hard requirements (no graceful degradation):

- Linux kernel >= 5.9 (BPF task iterators)
- Usable runtime kernel BTF at `/sys/kernel/btf/vmlinux`
- Ring buffer maps and helpers
- Tracing programs with `iter/task` attach support
- Capabilities: `CAP_BPF`, `CAP_PERFMON`, and `CAP_SYS_PTRACE` for best-effort `/proc` enrichment

Explicit non-fallbacks:

- No BTFHub download
- No embedded build-host BTF as a runtime substitute for iterator attach
- No `bpf_d_path` (helper starts in 5.10; executable path comes from best-effort `/proc/<pid>/exe`)

`internal/ebpf.ProbePrerequisites` encodes these checks and fails with actionable errors.

## Tooling

| Tool | Pin / note |
| --- | --- |
| `github.com/cilium/ebpf` | v0.20.0 |
| `bpf2go` | version-matched to cilium/ebpf v0.20.0 |
| clang/LLVM | Spike objects regenerated with Debian clang 19.1.7 (`golang:1.26` image) |
| bpftool | Optional for inspecting BTF; not required for ordinary builds |
| Host requirements for spike runs | Privileged Linux, `/sys/kernel/btf/vmlinux`, mounted `tracefs` (`/sys/kernel/tracing`) |

Regenerate spike objects with `internal/ebpf/spike/generate.sh`. Ordinary `go build` consumes committed generated bindings and does not require clang.

## Spike proofs

The spike under `internal/ebpf/spike` demonstrates:

1. CO-RE load of a `sched/sched_process_exec` tracepoint program that emits to a ring buffer
2. `iter/task` attachment and scan without `bpf_d_path`
3. Shared canonical maps across separately generated collections via `CollectionOptions.MapReplacements`
4. Race-safe startup prototype: start ringbuf reader, attach hot path, queue hot events, run iterator baseline keyed by `ProcessKey{PID,StartBootTime}`, replay pending events idempotently, then switch live
5. Best-effort `/proc/<pid>/{exe,cmdline}` enrichment that never replaces the iterator scan
6. Drop accounting for ringbuf reserve failures and bounded pending-queue pressure

Validated on Docker Desktop LinuxKit 6.12.76 (arm64) with privileged containers, mounted kernel BTF, and mounted tracefs. Example spike metrics: hot events queued during baseline and replayed (`pending_queued`/`replay_applied` > 0), ringbuf drops at zero under light load. Task-iterator snapshot counts reflect processes visible in the container PID namespace.

Run (privileged Linux host or container with kernel BTF mounted):

```bash
go test ./internal/ebpf -count=1
cd internal/ebpf/spike && ./generate.sh
go run ./internal/ebpf/spike/cmd/spike
```

## Windows coupling audit

Unguarded Windows imports that block a clean `GOOS=linux` build include (non-exhaustive; prioritize bootstrap and shared packages):

- `internal/bootstrap/bootstrap.go` (`golang.org/x/sys/windows`, `pkg/handle`)
- `internal/bootstrap/source.go` (hard-wires `etw.NewEventSource`)
- `cmd/fibratus/app/root.go` (runtime reject of non-Windows)
- Shared packages importing `golang.org/x/sys/windows` without build tags, notably: `pkg/event/enum.go`, `pkg/event/flags.go`, `pkg/config/output.go`, `pkg/filter/ql/function.go`, `pkg/util/log/logger.go`, `pkg/util/signals/signals.go`, `pkg/callstack/callstack.go`, `pkg/pe/parser.go`, `pkg/fs/*`, many `pkg/sys/*`, `pkg/handle/*`

Already Windows-tagged or stubbed in places: `pkg/config/eventsource.go`, `pkg/event/types_windows.go`, `pkg/ps/types/types_windows.go`, `pkg/yara/scanner_unsupported.go`, `pkg/cap/writer_unsupported.go`, `pkg/filament/filament_unsupported.go`.

## `ps.Snapshotter` consumer audit

Current interface methods used by Windows (full contract in `pkg/ps/snapshotter.go`): `Write`, `AddThread`, `AddModule`, `RemoveThread`, `RemoveModule`, `AddMmap`, `RemoveMmap`, `WriteFromCapture`, `Remove`, `Find`, `FindModule`, `FindAllModules`, `FindAndPut`, `Put`, `Size`, `Close`.

| Consumer | Needs on Linux | Migration |
| --- | --- | --- |
| `pkg/rules/engine.go` | `Find` only | Move to narrow `ps.Resolver` |
| `pkg/rules/compiler.go` | `Find` only | Move to `ps.Resolver` |
| `pkg/rules/sequence.go` | `Find` only | Move to `ps.Resolver` |
| `internal/bootstrap/*` | Construct platform snapshotter | Split `_windows` / `_linux` |
| `internal/etw/*` processors | Full Windows snapshotter | Keep Windows-only |
| `pkg/symbolize/*` | Modules / PE paths | Gate Windows-only; stub or omit on Linux |
| `pkg/yara/scanner.go` | Process memory context | Keep unsupported on Linux for now |
| `pkg/cap/*` | Capture restore | Out of initial Linux scope; keep stubs |
| `pkg/filament/*` | Process state for filaments | Out of initial Linux scope; keep stubs |
| `pkg/filter/filter_windows.go` | Optional psnap option | Linux filter path uses Linux accessors |

Recommended Linux contract: `ps.LinuxSnapshotter` with `Write`, `Remove`, `UpsertSnapshot`, `Find`, `Put`, `Size`, `Close`, plus thread/mmap state. Shared rules/sequence code must depend only on `ps.Resolver` (`Find`).

## Build gating worklist

Work required before a Linux process event source can land:

1. Build-tag split `internal/bootstrap` and replace ETW hard-wire with Linux eBPF source selection
2. Add `cmd/fibratus/main_linux.go` and per-OS command registration in `cmd/fibratus/app`
3. Add Linux `event.Type` semantic IDs (`uint16`, not syscall numbers) and `pkg/config/eventsource_linux.go`
4. Introduce `ps.Resolver` and migrate rules/compiler/sequence consumers
5. Add Linux PS types and `ProcessKey{PID,StartBootTime}`
6. Gate or stub remaining untagged Windows imports on the Linux build graph
7. Promote spike loader/consumer patterns into production `internal/ebpf` packages with committed generated objects and CI generation-drift checks
