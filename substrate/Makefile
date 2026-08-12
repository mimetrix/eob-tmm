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
        check-skeletons check-geometry check-shields gate clean

check: check-header check-schema check-offsets check-budget check-gates \
       check-skeletons check-geometry check-shields

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
