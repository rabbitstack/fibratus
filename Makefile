.DEFAULT_GOAL := build

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

BPF2GO_VERSION := v0.20.0
GOLANGCI_LINT_VERSION := v2.9.0
NFPM_VERSION := v2.43.0

# The committed objects are byte-compared in CI, and clang encodes its version
# into BTF, so generating with a different major produces a spurious diff.
CLANG_VERSION := 18

# The generated objects target x86-64 and the runtime refuses other
# architectures, so building the binary pins the same one.
TARGET_ARCH ?= amd64

# Specifies a list of build flags
TAGS ?=

BPF_DIR := internal/ebpf
BPF_OUT := $(BPF_DIR)/bpf

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
GO ?= go
GOFMT ?= gofmt
BPF2GO ?= go run github.com/cilium/ebpf/cmd/bpf2go@$(BPF2GO_VERSION)

BPF_FLAGS := \
	-go-package bpf \
	-output-dir $(BPF_OUT) \
	-cc $(CLANG) \
	-strip $(LLVM_STRIP) \
	-target bpfel,bpfeb \
	-tags linux

# Production headers first; spike/c is only the vmlinux.h fallback.
BPF_CFLAGS := \
	-I./$(BPF_DIR)/c \
	-I./$(BPF_DIR)/c/common \
	-I./$(BPF_DIR)/spike/c \
	-O2 \
	-g \
	-D__TARGET_ARCH_x86

# Find all eBPF sources.
BPF_SOURCES := $(wildcard $(BPF_DIR)/c/*.bpf.c)
BPF_NAMES := $(patsubst $(BPF_DIR)/c/%.bpf.c,%,$(BPF_SOURCES))
BPF_TARGETS := $(foreach name,$(BPF_NAMES), \
	$(BPF_OUT)/$(name)_bpfel.go \
	$(BPF_OUT)/$(name)_bpfeb.go)

titlecase = $(shell printf '%s' '$(1)' | awk '{print toupper(substr($$0,1,1)) substr($$0,2)}')

.PHONY: ebpf
ebpf: check-clang $(BPF_TARGETS)
$(BPF_OUT)/%_bpfel.go $(BPF_OUT)/%_bpfeb.go &: $(BPF_DIR)/c/%.bpf.c
	$(BPF2GO) $(BPF_FLAGS) -output-stem $* $(call titlecase,$*) $(BPF_DIR)/c/$*.bpf.c -- $(BPF_CFLAGS)

.PHONY: check-clang
check-clang:
	@command -v $(CLANG) >/dev/null 2>&1 || { \
		echo "$(CLANG) not found. Generating the eBPF objects needs clang $(CLANG_VERSION)."; \
		exit 1; \
	}
	@command -v $(LLVM_STRIP) >/dev/null 2>&1 || { \
		echo "$(LLVM_STRIP) not found. Versioned llvm packages ship llvm-strip-$(CLANG_VERSION)"; \
		echo "without the unversioned name bpf2go looks for."; \
		echo "Point LLVM_STRIP at it, e.g. make ebpf LLVM_STRIP=llvm-strip-$(CLANG_VERSION)."; \
		exit 1; \
	}
	@have=$$($(CLANG) --version | sed -n 's/.*clang version \([0-9]*\).*/\1/p' | head -1); \
	if [ "$$have" != "$(CLANG_VERSION)" ]; then \
		echo "clang $$have found but the committed objects were generated with $(CLANG_VERSION)."; \
		echo "Regenerating with another major rewrites every object and fails ebpf-drift."; \
		echo "Point CLANG at the right binary, e.g. make ebpf CLANG=clang-$(CLANG_VERSION)."; \
		exit 1; \
	fi

# Regenerating must be reproducible: same sources and same clang, same bytes.
.PHONY: ebpf-drift
ebpf-drift:
	$(MAKE) -B ebpf
	git diff --exit-code -- $(BPF_OUT)

ifeq ($(strip $(TAGS)),)
BUILD_TAGS :=
else
BUILD_TAGS := -tags $(TAGS)
endif

# Builds from the committed objects alone, so a fresh checkout needs no clang
# and no kernel headers. Naming the target pair keeps this buildable from a
# developer machine that is neither, which is the cheapest way to prove it.
.PHONY: build
build:
	GOOS=linux GOARCH=$(TARGET_ARCH) $(GO) build $(BUILD_TAGS) -o ./cmd/fibratus/fibratus ./cmd/fibratus/

.PHONY: fmt
fmt:
	$(GOFMT) -e -s -l -w pkg cmd internal

TEST_PKGS := \
	./internal/ebpf \
	./internal/bootstrap \
	./pkg/api \
	./pkg/config \
	./pkg/event \
	./pkg/filter \
	./pkg/ps \
	./pkg/rules \
	./pkg/rules/action \
	./pkg/util/signals

.PHONY: test
test:
	$(GO) test $(TEST_PKGS)

.PHONY: test-race
test-race:
	$(GO) test -race $(TEST_PKGS)

# Needs a 5.9+ kernel with runtime BTF, and root to load and attach.
.PHONY: test-integration
test-integration:
	$(GO) test -tags ebpf_integration -count=1 ./internal/ebpf

# Narrower than TEST_PKGS on purpose. Packages outside this set carry helpers
# that only Windows reaches, so `unused` reports them on every Linux run and
# there is nothing to fix without moving Windows code around.
LINT_PKGS := \
	./internal/ebpf/... \
	./internal/bootstrap/... \
	./pkg/filter/... \
	./pkg/rules/...

.PHONY: lint
lint:
	golangci-lint run $(LINT_PKGS)

VERSION ?= 0.0.0
PKG_DIR := build/pkg
NFPM ?= go run github.com/goreleaser/nfpm/v2/cmd/nfpm@$(NFPM_VERSION)

.PHONY: pkg
pkg: build
	@mkdir -p $(PKG_DIR)
	VERSION=$(VERSION) $(NFPM) package --config build/linux/nfpm.yaml --packager deb --target $(PKG_DIR)
	VERSION=$(VERSION) $(NFPM) package --config build/linux/nfpm.yaml --packager rpm --target $(PKG_DIR)

.PHONY: clean
clean:
	rm -f cmd/fibratus/fibratus
	rm -rf $(PKG_DIR)
