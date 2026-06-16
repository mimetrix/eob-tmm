# minimm — build the bent-pipe relay.
#
#   make             # Track 1: reference shield compiled in (runnable, no deps)
#   make ubpf        # Track 2 (real model): embedded uBPF VM (minimm-ubpf + minimm-trace)
#
# The synthetic-CVE translation unit is built WITHOUT the stack protector and
# with no optimization so the unchecked-opcode dispatch reliably faults instead
# of being optimized away.

CC      ?= cc
CLANG   ?= clang
CFLAGS  ?= -O0 -g -Wall -Wextra -fno-stack-protector -fno-omit-frame-pointer
LDFLAGS ?= -lrt

BIN = minimm

all: $(BIN)

# Track 1: reference shield compiled in (runnable, no external runtime).
$(BIN): minimm.c ls_shield.h
	$(CC) $(CFLAGS) -o $@ minimm.c $(LDFLAGS)

# ---- Track 2: embedded uBPF VM running the eBPF shield (the real model) ----
UBPF_DIR ?= ../../ubpf
UBPF_LIB := $(UBPF_DIR)/libubpf.a
SHIELD   := ../shields/ls_shield_ubpf.bpf.o
# BPF-target sysroot: multiarch dir on Debian/Ubuntu, harmless-if-absent on el8.
BPF_SYS  ?= -idirafter /usr/include/$(shell uname -m)-linux-gnu -idirafter /usr/include

# Build libubpf.a straight from the uBPF sources (no cmake/externals needed).
$(UBPF_LIB):
	printf '#pragma once\n#define UBPF_HAS_ELF_H\n' > $(UBPF_DIR)/vm/ubpf_config.h
	cd $(UBPF_DIR) && $(CC) -c -O2 -fPIC -Ivm -Ivm/inc $$(ls vm/*.c | grep -v '/test.c') \
	  && ar rcs libubpf.a *.o && rm -f *.o

# Compile the shields to eBPF bytecode (good + the deliberately-unsafe one used
# to demonstrate the §9 PREVAIL verify gate rejecting it).
BAD_SHIELD := ../shields/ls_shield_bad.bpf.o
$(SHIELD): ../shields/ls_shield_ubpf.bpf.c
	$(CLANG) -O2 -target bpf $(BPF_SYS) -c $< -o $@
$(BAD_SHIELD): ../shields/ls_shield_bad.bpf.c
	$(CLANG) -O2 -target bpf $(BPF_SYS) -c $< -o $@

minimm-ubpf: minimm.c ls_shield.h $(UBPF_LIB) $(SHIELD) $(BAD_SHIELD)
	$(CC) $(CFLAGS) -DLS_UBPF -I$(UBPF_DIR)/vm/inc -I$(UBPF_DIR)/vm \
	  -o $@ minimm.c $(UBPF_LIB) -lelf $(LDFLAGS)

# observe-mode build: same embedded VM, used as a TMM tracepoint (telemetry only)
TRACE_SHIELD := ../shields/ls_trace_ubpf.bpf.o
$(TRACE_SHIELD): ../shields/ls_trace_ubpf.bpf.c
	$(CLANG) -O2 -target bpf $(BPF_SYS) -c $< -o $@
minimm-trace: minimm.c ls_shield.h $(UBPF_LIB) $(TRACE_SHIELD)
	$(CC) $(CFLAGS) -DLS_TRACE -I$(UBPF_DIR)/vm/inc -I$(UBPF_DIR)/vm \
	  -o $@ minimm.c $(UBPF_LIB) -lelf $(LDFLAGS)

ubpf: minimm-ubpf minimm-trace

clean:
	rm -f $(BIN) minimm-ubpf minimm-trace $(SHIELD) $(BAD_SHIELD) $(TRACE_SHIELD) $(UBPF_LIB)
	-rm -f /dev/shm/minimm_ls

.PHONY: all ubpf clean
