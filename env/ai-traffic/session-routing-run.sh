#!/bin/bash
# Run inside the isolated fixture and retain both report exit statuses.
set -euo pipefail
run=${1:?provide a unique run name}
[[ "$run" =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
mkdir "/evidence/$run"
export ICAP_RESULT="/evidence/$run/result.json"
export ICAP_SUITE=session-routing
export PYTHONPATH="/work:${PYTHONPATH:-}"
export TAO_OUTPUT_FILE="/evidence/$run/tao.xml"
export TAO_TEST_PATH=/work/session_routing_suite.py
export TAO_TIME_OUT=210
export TAO_LOG_DISPLAY=all TAO_LOG_LEVEL=INFO
export CONFIG_SERVER_DPC_RAISE_ON_ERROR=false
set +e
tao_runner >"/evidence/$run/tao.log" 2>&1
status=$?
printf '%s\n' "$status" >"/evidence/$run/exit-status"
if [[ "$status" == 0 ]]; then
    python3 /work/icap_check_result.py "/evidence/$run"
    status=$?
fi
printf '%s\n' "$status" >"/evidence/$run/checked-exit-status"
exit "$status"
