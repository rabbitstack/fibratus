.DEFAULT_GOAL := build

SHELL=bash -o pipefail -e

BPF2GO_VERSION := v0.20.0

# Specifies a list of build flags
TAGS ?= ""

BPF_DIR := internal/ebpf

BPF_FLAGS := \
	-go-package bpf \
	-output-dir $(BPF_DIR)/bpf \
	-cc clang \
	-target bpfel,bpfeb \
	-tags linux

BPF_CFLAGS := \
	-I./$(BPF_DIR)/spike/c \
	-I./$(BPF_DIR)/c \
	-I./$(BPF_DIR)/c/common \
	-O2 \
	-g \
	-D__TARGET_ARCH_x86

# Find all eBPF sources.
BPF_SOURCES := $(wildcard $(BPF_DIR)/c/*.bpf.c)
BPF_NAMES := $(patsubst $(BPF_DIR)/c/%.bpf.c,%,$(BPF_SOURCES))
BPF_TARGETS := $(foreach name,$(BPF_NAMES), \
	$(BPF_DIR)/$(name)_bpfel.go \
	$(BPF_DIR)/$(name)_bpfeb.go)

CLANG ?= clang
GO ?= go
GOFMT ?= gofmt
BPF2GO ?= go run github.com/cilium/ebpf/cmd/bpf2go@$(BPF2GO_VERSION)

.PHONY: ebpf
ebpf: $(BPF_TARGETS)
$(BPF_DIR)/%_bpfel.go $(BPF_DIR)/%_bpfeb.go &: $(BPF_DIR)/c/%.bpf.c
	$(BPF2GO) $(BPF_FLAGS) -output-stem $* $(shell echo $* | sed 's/^./\U&/') $(BPF_DIR)/c/$*.bpf.c -- $(BPF_CFLAGS)

.PHONY: build
build:
	$(GO) build -tags $(TAGS) -o ./cmd/fibratus/fibratus ./cmd/fibratus/

.PHONY: fmt
fmt:
	$(GOFMT) -e -s -l -w pkg cmd

.PHONY: test
test:
	$(GO) test ./...

.PHONY: clean
clean:
	rm -f cmd/fibratus/fibratus
