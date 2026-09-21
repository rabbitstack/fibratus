.DEFAULT_GOAL := build

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

BPF2GO_VERSION := v0.20.0

# Specifies a list of build flags
TAGS ?=

BPF_DIR := internal/ebpf
BPF_OUT := $(BPF_DIR)/bpf

CLANG ?= clang
GO ?= go
GOFMT ?= gofmt
BPF2GO ?= go run github.com/cilium/ebpf/cmd/bpf2go@$(BPF2GO_VERSION)

BPF_FLAGS := \
	-go-package bpf \
	-output-dir $(BPF_OUT) \
	-cc $(CLANG) \
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
ebpf: $(BPF_TARGETS)
$(BPF_OUT)/%_bpfel.go $(BPF_OUT)/%_bpfeb.go &: $(BPF_DIR)/c/%.bpf.c
	$(BPF2GO) $(BPF_FLAGS) -output-stem $* $(call titlecase,$*) $(BPF_DIR)/c/$*.bpf.c -- $(BPF_CFLAGS)

ifeq ($(strip $(TAGS)),)
BUILD_TAGS :=
else
BUILD_TAGS := -tags $(TAGS)
endif

.PHONY: build
build:
	$(GO) build $(BUILD_TAGS) -o ./cmd/fibratus/fibratus ./cmd/fibratus/

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

.PHONY: clean
clean:
	rm -f cmd/fibratus/fibratus
