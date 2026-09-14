#!/usr/bin/env bash
# Regenerate bpf2go bindings for the Linux eBPF process source.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if ! command -v clang >/dev/null 2>&1; then
  echo "clang is required to regenerate eBPF objects" >&2
  exit 1
fi

# The process source is x86_64-only. Always compile CO-RE objects for that
# architecture so generation is host-independent.
export BPF_TARGET_ARCH=x86

CLANG_VERSION="$(clang --version | head -n1)"
echo "clang: ${CLANG_VERSION}"
echo "target arch: ${BPF_TARGET_ARCH}"

INCLUDES=(-I./c -I./c/common -I./spike/c -O2 -g "-D__TARGET_ARCH_${BPF_TARGET_ARCH}")

generate() {
  local name="$1"
  local src="$2"
  go run github.com/cilium/ebpf/cmd/bpf2go@v0.20.0 \
    -go-package ebpf -output-dir . -cc clang -target bpfel,bpfeb -tags linux \
    "${name}" "${src}" -- "${INCLUDES[@]}"
}

generate execve ./c/execve.bpf.c
generate exit ./c/exit.bpf.c
generate clone ./c/clone.bpf.c
generate prociter ./c/proc_iter.bpf.c

echo "generated eBPF bindings"
