#!/usr/bin/env bash
# Regenerate bpf2go bindings for the Linux eBPF spike.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if ! command -v clang >/dev/null 2>&1; then
  echo "clang is required to regenerate eBPF objects" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64) export BPF_TARGET_ARCH=x86 ;;
  aarch64|arm64) export BPF_TARGET_ARCH=arm64 ;;
  *)
    echo "unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

CLANG_VERSION="$(clang --version | head -n1)"
echo "clang: ${CLANG_VERSION}"
echo "target arch: ${BPF_TARGET_ARCH}"

go run github.com/cilium/ebpf/cmd/bpf2go@v0.20.0 \
  -go-package spike -output-dir . -cc clang -target bpfel,bpfeb \
  execve ./c/execve.bpf.c -- -I./c -O2 -g "-D__TARGET_ARCH_${BPF_TARGET_ARCH}"

go run github.com/cilium/ebpf/cmd/bpf2go@v0.20.0 \
  -go-package spike -output-dir . -cc clang -target bpfel,bpfeb \
  prociter ./c/proc_iter.bpf.c -- -I./c -O2 -g "-D__TARGET_ARCH_${BPF_TARGET_ARCH}"

echo "generated spike bpf bindings"
