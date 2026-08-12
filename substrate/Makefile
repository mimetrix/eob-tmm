# substrate/Makefile — verification only. There is nothing to build here: this
# directory holds the two candidate ABI artifacts, not a program.
#
#   make check    syntax-check shield_abi.h (incl. its wire-layout asserts) and
#                 validate hook-point-map.json against the schema.
#
# See README.md for what is real vs. illustrative, and ../development-scope-code.md
# for the per-item skeletons that use this ABI.

CC     ?= cc
PYTHON ?= python3

.PHONY: check check-header check-schema check-offsets check-budget check-gates \
        check-skeletons check-geometry check-shields check-stack check-vm gate clean

check: check-header check-schema check-offsets check-budget check-gates \
       check-skeletons check-geometry check-shields check-stack check-vm

# The header must compile standalone, be include-guard clean, and its
# _Static_asserts on struct shield_msg's layout must hold.
check-header:
	@$(CC) -fsyntax-only -x c shield_abi.h && echo "ok    shield_abi.h  (syntax)"
	@printf '#include "shield_abi.h"\n#include "shield_abi.h"\nint main(void){return (int)sizeof(struct shield_msg);}\n' > .guard.c
	@$(CC) -I. -o .guard.out .guard.c && echo "ok    shield_abi.h  (include guard + wire-layout asserts)"
	@rm -f .guard.c .guard.out

check-schema:
	@$(PYTHON) -m json.tool hook_map.schema.json > /dev/null && echo "ok    hook_map.schema.json  (valid JSON)"
	@$(PYTHON) ./check_hook_map.py

# The check a real hook-map generator must have: compile the map's declared ctx
# offsets against the actual header and fail on mismatch. Offsets are verified,
# not trusted — see the note at the top of check_offsets.py for the live bug in
# this repo that this catches.
check-offsets:
	@$(PYTHON) ./check_offsets.py

# The budget pass, over its own self-test cases: hand-assembled eBPF in a
# synthesized ELF, covering lddw's 16-byte form, longest-path over a branch, a
# fail-closed budget, and refusing a loop rather than guessing its trip count.
check-budget:
	@$(PYTHON) ./budget_pass.py

# The safe-return two-gate rule, asserted rather than documented: an unanalysed
# body must never be enforce-capable, whatever its return type. See F3 in
# ../../design-review-findings.md for the review that caught the inverted model.
check-gates:
	@$(CC) -I. -o .gates.out check_sr_gates.c && ./.gates.out; rc=$$?; rm -f .gates.out; exit $$rc

# The skeletons in ../development-scope-code.md, actually handed to a compiler.
# They are the exemplar an engineer reads for the shape of each item, and until
# this target existed no compiler had read them — which is how the JIT typedef
# came to be the 2-arg basic form while the design needs the 4-arg extended one.
# A block may opt out with a `not-compiled:` reason, and opting out is reported,
# never silent.
check-skeletons:
	@$(PYTHON) ./check_skeletons.py

# Item 6a: does the verifier's model of the runtime match the runtime? Parsed
# from the two vendored trees at run time rather than transcribed. Reports;
# `make gate` is the same check with the exit code a build pipeline needs.
check-geometry:
	@$(PYTHON) ./check_vm_geometry.py

# Item 6a's resolution: the stack-usage calculator that makes uBPF allocate what
# PREVAIL proved against. Asserts the behaviour that matters — it must never return
# 0, because uBPF's header says 0 means "assume the maximum" and its code gives a
# zero-byte frame.
check-stack:
	@$(CC) -fsyntax-only -x c vm_stack_policy.h && echo "ok    vm_stack_policy.h  (syntax + _Static_asserts)"
	@printf '#include "vm_stack_policy.h"\n#include "vm_stack_policy.h"\n#include <assert.h>\nint main(void){\n struct vm_stack_policy g={256,8},bad0={0,8},mis={100,8},deep={512,9};\n assert(vm_stack_policy_valid(&g)); assert(!vm_stack_policy_valid(&bad0));\n assert(!vm_stack_policy_valid(&mis)); assert(!vm_stack_policy_valid(&deep));\n assert(!vm_stack_policy_valid(0));\n assert(vm_stack_usage(0,0,&g)==256);\n assert(vm_stack_usage(0,0,0)==512);\n assert(vm_stack_usage(0,0,&bad0)==512);\n assert(vm_stack_align_up(1)==16&&vm_stack_align_up(16)==16&&vm_stack_align_up(17)==32);\n return 0;}\n' > .vsp.c
	@$(CC) -I. -o .vsp.out .vsp.c && ./.vsp.out && echo "ok    vm_stack_policy.h  (9 assertions, incl. never-return-0)"
	@rm -f .vsp.c .vsp.out

# The embedded VM itself: the ~120 lines that make "TMM has its own BPF VM" true.
# Compiled against the REAL vendored uBPF headers, so a signature drift upstream
# fails here rather than at integration time. Compiled, not linked or run.
check-vm:
	@$(CC) -fsyntax-only -Wall -Wextra -I. -I../ubpf/vm/inc -I../ubpf/vm ls_vm.c \
	  && echo "ok    ls_vm.c  (compiles against the real uBPF API, -Wall -Wextra clean)"

# The candidate shields in shields/, compiled and put to PREVAIL, with each verdict
# asserted. A rejection program that starts passing is the dangerous direction, so both
# directions are failures. Skips loudly if clang has no BPF target or prevail is unbuilt.
check-shields:
	@$(PYTHON) ./check_shields.py

# Everything in `check`, plus the standing findings turned fatal. This is what a
# real admission pipeline would run. It FAILS today, on purpose: item 6a is open.
gate: check
	@$(PYTHON) ./check_vm_geometry.py --gate

clean:
	@rm -f .guard.c .guard.out .gates.out tmp*.c
	@rm -rf __pycache__
