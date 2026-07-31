# substrate/Makefile — verification only. There is nothing to build here: this
# directory holds the two candidate ABI artifacts, not a program.
#
#   make check    syntax-check shield_abi.h (incl. its wire-layout asserts) and
#                 validate prototype/hook-point-map.json against the schema.
#
# See README.md for what is real vs. illustrative, and ../../development-scope-code.md
# for the per-item skeletons that use this ABI.

CC     ?= cc
PYTHON ?= python3

.PHONY: check check-header check-schema check-offsets check-budget check-gates clean

check: check-header check-schema check-offsets check-budget check-gates

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

# The budget pass, run for real against the repo's own shield objects. It parses
# the ELF, decodes the instruction stream (including lddw's 16-byte form), builds
# the CFG and prices the longest path. Refuses anything with an unproven loop.
check-budget:
	@$(PYTHON) ./budget_pass.py

# The safe-return two-gate rule, asserted rather than documented: an unanalysed
# body must never be enforce-capable, whatever its return type. See F3 in
# ../../design-review-findings.md for the review that caught the inverted model.
check-gates:
	@$(CC) -I. -o .gates.out check_sr_gates.c && ./.gates.out; rc=$$?; rm -f .gates.out; exit $$rc

clean:
	@rm -f .guard.c .guard.out .gates.out tmp*.c
