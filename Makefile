.DEFAULT_GOAL := build

SHELL=bash -o pipefail -e
UNAME=$(shell uname -r)
# Override this if the target linux headers path differs
LINUX_HEADERS ?= /lib/modules/$(UNAME)

CLANG ?= clang
LLC ?= llc
GO ?= go
GOFMT ?= gofmt

# Specifies a list of build flags
TAGS ?= ""

# Compiler flags for building the kprobe object
CFLAGS = -I $(LINUX_HEADERS)/build/arch/x86/include \
        -I $(LINUX_HEADERS)/build/arch/x86/include/generated/uapi \
        -I $(LINUX_HEADERS)/build/arch/x86/include/generated \
        -I $(LINUX_HEADERS)/build/include \
        -I $(LINUX_HEADERS)/build/arch/x86/include/uapi \
        -I $(LINUX_HEADERS)/build/include/uapi \
        -include $(LINUX_HEADERS)/build/include/linux/kconfig.h \
        -I $(LINUX_HEADERS)/build/include/generated/uapi \
        -D__KERNEL__ -D__ASM_SYSREG_H \
        -DKBUILD_MODNAME='"kprobe"' \
        -Wunused \
        -Wall \
        -Wno-compare-distinct-pointer-types \
        -fno-stack-protector \
        -Wno-pointer-sign \
        -O2 -S -emit-llvm

.PHONY: build
build:
	$(GO) build -tags $(TAGS) -o ./cmd/fibratus/fibratus ./cmd/fibratus/

.PHONY: fmt
fmt:
	$(GOFMT) -e -s -l -w pkg cmd

KPROBE_PROG := pkg/kstream/kprobe.o
pkg/kstream/kprobe.o: pkg/ebpf/c/kprobe.c
	$(CLANG) $(CFLAGS) -c $< -o - | $(LLC) -march=bpf -mcpu=$(CPU) -filetype=obj -o $@

.PHONY: kprobe
kprobe: $(KPROBE_PROG)

.PHONY: clean
clean:
	rm -f cmd/fibratus/fibratus
	rm -f pkg/kstream/kprobe.o


