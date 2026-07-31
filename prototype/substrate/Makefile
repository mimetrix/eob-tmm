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

.PHONY: check check-header check-schema check-offsets clean

check: check-header check-schema check-offsets

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

clean:
	@rm -f .guard.c .guard.out tmp*.c
